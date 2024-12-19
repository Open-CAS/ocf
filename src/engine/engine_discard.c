/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "cache_engine.h"
#include "engine_common.h"
#include "engine_discard.h"
#include "engine_io.h"
#include "../metadata/metadata.h"
#include "../ocf_request.h"
#include "../utils/utils_io.h"
#include "../concurrency/ocf_concurrency.h"

#define OCF_ENGINE_DEBUG 0

#define OCF_ENGINE_DEBUG_IO_NAME "discard"
#include "engine_debug.h"

static void _ocf_discard_complete_req(struct ocf_request *req, int error)
{
	req->complete(req, error);

	ocf_req_put(req);
}

static int _ocf_discard_core(struct ocf_request *req)
{
	req->addr = SECTORS_TO_BYTES(req->discard.sector);
	req->bytes = SECTORS_TO_BYTES(req->discard.nr_sects);

	ocf_engine_forward_core_discard_req(req, _ocf_discard_complete_req);

	return 0;
}

static void _ocf_discard_cache_flush_complete(struct ocf_request *req, int error)
{
	if (error) {
		ocf_metadata_error(req->cache);
		_ocf_discard_complete_req(req, error);
		return;
	}

	req->engine_handler = _ocf_discard_core;
	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

static int _ocf_discard_flush_cache(struct ocf_request *req)
{
	ocf_engine_forward_cache_flush_req(req,
			_ocf_discard_cache_flush_complete);

	return 0;
}

static int _ocf_discard_step(struct ocf_request *req);

static void _ocf_discard_finish_step(struct ocf_request *req)
{
	req->discard.handled += BYTES_TO_SECTORS(req->bytes);

	if (req->discard.handled < req->discard.nr_sects)
		req->engine_handler = _ocf_discard_step;
	else if (!req->cache->metadata.is_volatile)
		req->engine_handler = _ocf_discard_flush_cache;
	else
		req->engine_handler = _ocf_discard_core;

	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

static void _ocf_discard_step_complete(struct ocf_request *req, int error)
{
	if (env_atomic_dec_return(&req->req_remaining))
		return;

	OCF_DEBUG_RQ(req, "Completion");

	/* Release WRITE lock of request */
	ocf_req_unlock_wr(ocf_cache_line_concurrency(req->cache), req);

	if (error) {
		ocf_metadata_error(req->cache);
		_ocf_discard_complete_req(req, error);
		return;
	}

	_ocf_discard_finish_step(req);
}

static int _ocf_discard_step_do(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	env_atomic_set(&req->req_remaining, 1); /* One core IO */

	if (ocf_engine_mapped_count(req)) {
		/* There are mapped cache line, need to remove them */

		ocf_hb_req_prot_lock_wr(req);

		/* Remove mapped cache lines from metadata */
		ocf_purge_map_info(req);

		ocf_hb_req_prot_unlock_wr(req);

		if (req->info.flush_metadata) {
			env_atomic_inc(&req->req_remaining);

			/* Request was dirty and need to flush metadata */
			ocf_metadata_flush_do_asynch(cache, req,
					_ocf_discard_step_complete);
		}
	}

	ocf_hb_req_prot_lock_rd(req);

	/* Even if no cachelines are mapped they could be tracked in promotion
	 * policy. RD lock suffices. */
	ocf_promotion_req_purge(req->cache->promotion_policy, req);

	ocf_hb_req_prot_unlock_rd(req);

	OCF_DEBUG_RQ(req, "Discard");
	_ocf_discard_step_complete(req, 0);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}

static void _ocf_discard_on_resume(struct ocf_request *req)
{
	OCF_DEBUG_RQ(req, "On resume");
	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

static int _ocf_discard_step(struct ocf_request *req)
{
	int lock;
	struct ocf_cache *cache = req->cache;

	OCF_DEBUG_TRACE(req->cache);

	req->addr = SECTORS_TO_BYTES(req->discard.sector +
			req->discard.handled);
	req->bytes = OCF_MIN(SECTORS_TO_BYTES(req->discard.nr_sects -
			req->discard.handled), MAX_TRIM_RQ_SIZE);
	req->core_line_first = ocf_bytes_2_lines(cache, req->addr);
	req->core_line_last =
		ocf_bytes_2_lines(cache, req->addr + req->bytes - 1);
	req->core_line_count = req->core_line_last - req->core_line_first + 1;
	req->engine_handler = _ocf_discard_step_do;

	ENV_BUG_ON(env_memset(req->map, sizeof(*req->map) * req->core_line_count,
			0));

	ocf_req_hash(req);
	ocf_hb_req_prot_lock_rd(req);

	/* Travers to check if request is mapped fully */
	ocf_engine_lookup(req);

	if (ocf_engine_mapped_count(req)) {
		/* Some cache line are mapped, lock request for WRITE access */
		lock = ocf_req_async_lock_wr(
				ocf_cache_line_concurrency(cache),
				req, _ocf_discard_on_resume);
	} else {
		lock = OCF_LOCK_ACQUIRED;
	}

	ocf_hb_req_prot_unlock_rd(req);

	if (lock >= 0) {
		if (OCF_LOCK_ACQUIRED == lock) {
			ocf_debug_request_trace(req, ocf_req_cache_mode_discard, 0);
			_ocf_discard_step_do(req);
		} else {
			/* WR lock was not acquired, need to wait for resume */
			ocf_debug_request_trace(req, ocf_req_cache_mode_discard, 1);
			OCF_DEBUG_RQ(req, "NO LOCK")
		}
	} else {
		OCF_DEBUG_RQ(req, "LOCK ERROR %d", lock);
		req->error |= lock;
		_ocf_discard_finish_step(req);
	}

	env_cond_resched();

	return 0;
}

int ocf_engine_discard(struct ocf_request *req)
{
	OCF_DEBUG_TRACE(req->cache);


	if (req->rw == OCF_READ) {
		req->complete(req, -OCF_ERR_INVAL);
		ocf_req_put(req);
		return 0;
	}

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	_ocf_discard_step(req);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}
