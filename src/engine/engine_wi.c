/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_wi.h"
#include "engine_common.h"
#include "../concurrency/ocf_concurrency.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_io.h"
#include "../metadata/metadata.h"

#define OCF_ENGINE_DEBUG_IO_NAME "wi"
#include "engine_debug.h"

static int ocf_write_wi_update_and_flush_metadata(struct ocf_request *rq);

static const struct ocf_io_if _io_if_wi_flush_metadata = {
		.read = ocf_write_wi_update_and_flush_metadata,
		.write = ocf_write_wi_update_and_flush_metadata,
};

static void _ocf_write_wi_io_flush_metadata(void *private_data, int error)
{
	struct ocf_request *rq = (struct ocf_request *) private_data;

	if (error) {
		env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				cache_errors.write);
		rq->error |= error;
	}

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	if (rq->error)
		ocf_engine_error(rq, true, "Failed to write data to cache");

	ocf_rq_unlock_wr(rq);

	rq->complete(rq, rq->error);

	ocf_rq_put(rq);
}

static int ocf_write_wi_update_and_flush_metadata(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	env_atomic_set(&rq->req_remaining, 1); /* One core IO */

	if (ocf_engine_mapped_count(rq)) {
		/* There are mapped cache line, need to remove them */

		OCF_METADATA_LOCK_WR(); /*- Metadata WR access ---------------*/

		/* Remove mapped cache lines from metadata */
		ocf_purge_map_info(rq);

		OCF_METADATA_UNLOCK_WR(); /*- END Metadata WR access ---------*/

		if (rq->info.flush_metadata) {
			/* Request was dirty and need to flush metadata */
			ocf_metadata_flush_do_asynch(cache, rq,
					_ocf_write_wi_io_flush_metadata);
		}

	}

	_ocf_write_wi_io_flush_metadata(rq, 0);

	return 0;
}

static void _ocf_write_wi_core_io(void *private_data, int error)
{
	struct ocf_request *rq = private_data;

	if (error) {
		rq->error = error;
		rq->info.core_error = 1;
		env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				core_errors.write);
	}

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	OCF_DEBUG_RQ(rq, "Completion");

	if (rq->error) {
		ocf_rq_unlock_wr(rq);

		rq->complete(rq, rq->error);

		ocf_rq_put(rq);
	} else {
		ocf_engine_push_rq_front_if(rq, &_io_if_wi_flush_metadata,
				true);
	}
}

static int _ocf_write_wi_do(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	env_atomic_set(&rq->req_remaining, 1); /* One core IO */

	OCF_DEBUG_RQ(rq, "Submit");

	/* Submit write IO to the core */
	ocf_submit_obj_req(&cache->core_obj[rq->core_id].obj, rq, OCF_WRITE,
			   _ocf_write_wi_core_io, rq);

	/* Update statistics */
	ocf_engine_update_block_stats(rq);
	env_atomic64_inc(&cache->core_obj[rq->core_id].counters->
			part_counters[rq->part_id].write_reqs.pass_through);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}

static void _ocf_write_wi_on_resume(struct ocf_request *rq)
{
	OCF_DEBUG_RQ(rq, "On resume");
	ocf_engine_push_rq_front(rq, true);
}

static const struct ocf_io_if _io_if_wi_resume = {
	.read = _ocf_write_wi_do,
	.write = _ocf_write_wi_do,
};

int ocf_write_wi(struct ocf_request *rq)
{
	int lock = OCF_LOCK_NOT_ACQUIRED;
	struct ocf_cache *cache = rq->cache;

	OCF_DEBUG_TRACE(rq->cache);

	ocf_io_start(rq->io);

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* Set resume call backs */
	rq->resume = _ocf_write_wi_on_resume;
	rq->io_if = &_io_if_wi_resume;

	OCF_METADATA_LOCK_RD(); /*- Metadata READ access, No eviction --------*/

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
		if (lock == OCF_LOCK_ACQUIRED) {
			_ocf_write_wi_do(rq);
		} else {
			/* WR lock was not acquired, need to wait for resume */
			OCF_DEBUG_RQ(rq, "NO LOCK");
		}
	} else {
		OCF_DEBUG_RQ(rq, "LOCK ERROR %d", lock);
		rq->complete(rq, lock);
		ocf_rq_put(rq);
	}

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}
