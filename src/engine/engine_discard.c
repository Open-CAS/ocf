/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "cache_engine.h"
#include "engine_common.h"
#include "engine_discard.h"
#include "../metadata/metadata.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_io.h"
#include "../utils/utils_cache_line.h"
#include "../concurrency/ocf_concurrency.h"

#define OCF_ENGINE_DEBUG 0

#define OCF_ENGINE_DEBUG_IO_NAME "discard"
#include "engine_debug.h"

static int _ocf_discard_step_do(struct ocf_request *rq);
static int _ocf_discard_step(struct ocf_request *rq);
static int _ocf_discard_flush_cache(struct ocf_request *rq);
static int _ocf_discard_core(struct ocf_request *rq);

static const struct ocf_io_if _io_if_discard_step = {
	.read = _ocf_discard_step,
	.write = _ocf_discard_step
};

static const struct ocf_io_if _io_if_discard_step_resume = {
	.read = _ocf_discard_step_do,
	.write = _ocf_discard_step_do
};

static const struct ocf_io_if _io_if_discard_flush_cache = {
	.read = _ocf_discard_flush_cache,
	.write = _ocf_discard_flush_cache,
};

static const struct ocf_io_if _io_if_discard_core = {
	.read = _ocf_discard_core,
	.write = _ocf_discard_core
};

static void _ocf_discard_complete_rq(struct ocf_request *rq, int error)
{
	rq->complete(rq, error);

	ocf_rq_put(rq);
}

static void _ocf_discard_core_io(void *private_data, int error)
{
	struct ocf_request *rq = private_data;

	OCF_DEBUG_RQ(rq, "Core DISCARD Completion");

	_ocf_discard_complete_rq(rq, error);
}

static int _ocf_discard_core(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	ocf_submit_obj_discard(&cache->core_obj[rq->core_id].obj, rq,
			_ocf_discard_core_io, rq);

	return 0;
}

static void _ocf_discard_cache_flush_io_cmpl(void *priv, int error)
{
	struct ocf_request *rq = priv;

	if (error) {
		ocf_metadata_error(rq->cache);
		_ocf_discard_complete_rq(rq, error);
		return;
	}

	rq->io_if = &_io_if_discard_core;
	ocf_engine_push_rq_front(rq, true);
}

static int _ocf_discard_flush_cache(struct ocf_request *rq)
{
	ocf_submit_obj_flush(&rq->cache->device->obj,
			_ocf_discard_cache_flush_io_cmpl, rq);

	return 0;
}

static void _ocf_discard_finish_step(struct ocf_request *rq)
{
	rq->discard.handled += BYTES_TO_SECTORS(rq->byte_length);

	if (rq->discard.handled < rq->discard.nr_sects)
		rq->io_if = &_io_if_discard_step;
	else if (rq->cache->device->init_mode != ocf_init_mode_metadata_volatile)
		rq->io_if = &_io_if_discard_flush_cache;
	else
		rq->io_if = &_io_if_discard_core;

	ocf_engine_push_rq_front(rq, true);
}

static void _ocf_discard_step_io(void *private_data, int error)
{
	struct ocf_request *rq = private_data;

	if (error)
		rq->error |= error;

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	OCF_DEBUG_RQ(rq, "Completion");

	/* Release WRITE lock of request */
	ocf_rq_unlock_wr(rq);

	if (rq->error) {
		ocf_metadata_error(rq->cache);
		_ocf_discard_complete_rq(rq, rq->error);
		return;
	}

	_ocf_discard_finish_step(rq);
}

int _ocf_discard_step_do(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	env_atomic_set(&rq->req_remaining, 1); /* One core IO */

	if (ocf_engine_mapped_count(rq)) {
		/* There are mapped cache line, need to remove them */

		OCF_METADATA_LOCK_WR(); /*- Metadata WR access ---------------*/

		/* Remove mapped cache lines from metadata */
		ocf_purge_map_info(rq);

		if (rq->info.flush_metadata) {
			/* Request was dirty and need to flush metadata */
			ocf_metadata_flush_do_asynch(cache, rq,
					_ocf_discard_step_io);
		}

		OCF_METADATA_UNLOCK_WR(); /*- END Metadata WR access ---------*/
	}

	OCF_DEBUG_RQ(rq, "Discard");
	_ocf_discard_step_io(rq, 0);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}

static void _ocf_discard_on_resume(struct ocf_request *rq)
{
	OCF_DEBUG_RQ(rq, "On resume");
	ocf_engine_push_rq_front(rq, true);
}

static int _ocf_discard_step(struct ocf_request *rq)
{
	int lock;
	struct ocf_cache *cache = rq->cache;

	OCF_DEBUG_TRACE(rq->cache);

	rq->byte_position = SECTORS_TO_BYTES(rq->discard.sector +
			rq->discard.handled);
	rq->byte_length = MIN(SECTORS_TO_BYTES(rq->discard.nr_sects -
			rq->discard.handled), MAX_TRIM_RQ_SIZE);
	rq->core_line_first = ocf_bytes_2_lines(cache, rq->byte_position);
	rq->core_line_last =
		ocf_bytes_2_lines(cache, rq->byte_position + rq->byte_length - 1);
	rq->core_line_count = rq->core_line_last - rq->core_line_first + 1;
	rq->io_if = &_io_if_discard_step_resume;

	OCF_METADATA_LOCK_RD(); /*- Metadata READ access, No eviction --------*/

	ENV_BUG_ON(env_memset(rq->map, sizeof(*rq->map) * rq->core_line_count,
			0));

	/* Travers to check if request is mapped fully */
	ocf_engine_traverse(rq);

	if (ocf_engine_mapped_count(rq)) {
		/* Some cache line are mapped, lock request for WRITE access */
		lock = ocf_rq_trylock_wr(rq);
	} else {
		lock = OCF_LOCK_ACQUIRED;
	}

	OCF_METADATA_UNLOCK_RD(); /*- END Metadata READ access----------------*/

	if (lock >= 0) {
		if (OCF_LOCK_ACQUIRED == lock) {
			_ocf_discard_step_do(rq);
		} else {
			/* WR lock was not acquired, need to wait for resume */
			OCF_DEBUG_RQ(rq, "NO LOCK")
		}
	} else {
		OCF_DEBUG_RQ(rq, "LOCK ERROR %d", lock);
		rq->error |= lock;
		_ocf_discard_finish_step(rq);
	}

	env_cond_resched();

	return 0;
}

int ocf_discard(struct ocf_request *rq)
{
	OCF_DEBUG_TRACE(rq->cache);

	ocf_io_start(rq->io);

	if (rq->rw == OCF_READ) {
		rq->complete(rq, -EINVAL);
		return 0;
	}

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* Set resume call backs */
	rq->resume = _ocf_discard_on_resume;

	_ocf_discard_step(rq);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}
