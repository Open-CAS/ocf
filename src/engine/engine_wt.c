/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_wt.h"
#include "engine_wi.h"
#include "engine_inv.h"
#include "engine_common.h"
#include "engine_io.h"
#include "../ocf_request.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_user_part.h"
#include "../metadata/metadata.h"
#include "../concurrency/ocf_concurrency.h"

#define OCF_ENGINE_DEBUG_IO_NAME "wt"
#include "engine_debug.h"

static void _ocf_write_wt_update_bits(struct ocf_request *req)
{
	bool miss = ocf_engine_is_miss(req);
	bool dirty_any = req->info.dirty_any;
	bool repart = ocf_engine_needs_repart(req);

	if (!miss && !dirty_any && !repart)
		return;

	ocf_hb_req_prot_lock_wr(req);

	if (miss) {
		/* Update valid status bits */
		ocf_set_valid_map_info(req);
	}

	if (dirty_any) {
		/* Writes goes to both cache and core, need to update
		 * status bits from dirty to clean
		 */
		ocf_set_clean_map_info(req);
	}

	if (repart) {
		OCF_DEBUG_RQ(req, "Re-Part");
		/* Probably some cache lines are assigned into wrong
		 * partition. Need to move it to new one
		 */
		ocf_user_part_move(req);
	}

	ocf_hb_req_prot_unlock_wr(req);
}

static void _ocf_write_wt_do_flush_metadata_compl(struct ocf_request *req,
		int error)
{
	if (error)
		ocf_engine_error(req, true, "Failed to write data to cache");

	ocf_req_unlock_wr(ocf_cache_line_concurrency(req->cache), req);

	req->complete(req, error);

	ocf_req_put(req);
}

static int ocf_write_wt_do_flush_metadata(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	_ocf_write_wt_update_bits(req);

	if (req->info.flush_metadata) {
		/* Metadata flush IO */

		ocf_metadata_flush_do_asynch(cache, req,
				_ocf_write_wt_do_flush_metadata_compl);
	} else {
		_ocf_write_wt_do_flush_metadata_compl(req, 0);
	}

	return 0;
}

static void _ocf_write_wt_req_complete(struct ocf_request *req)
{
	if (env_atomic_dec_return(&req->req_remaining))
		return;

	OCF_DEBUG_RQ(req, "Completion");

	if (req->info.cache_error || req->info.core_error) {
		req->complete(req, req->error);
		ocf_engine_invalidate(req);
		return;
	}

	if (req->info.dirty_any) {
		/* Some of the request's cachelines changed its state to clean */
		ocf_queue_push_req_cb(req, ocf_write_wt_do_flush_metadata,
				OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
	} else {
		ocf_req_unlock_wr(ocf_cache_line_concurrency(req->cache), req);
		req->complete(req, 0);
		ocf_req_put(req);
	}
}

static void _ocf_write_wt_cache_complete(struct ocf_request *req, int error)
{
	if (error) {
		/* Cache error code is not propagated further to the user here
		 * because data could be successfully written to the core device
		 * despite the cache IO error.
		 * Error flag is set though to indicate that the error occurred
		 * and to invalidate the request in completion. */
		req->info.cache_error = 1;
		ocf_core_stats_cache_error_update(req->core, OCF_WRITE);
		inc_fallback_pt_error_counter(req->cache);
	}

	_ocf_write_wt_req_complete(req);
}

static void _ocf_write_wt_core_complete(struct ocf_request *req, int error)
{
	if (error) {
		req->info.core_error = 1;
		req->error = error;
		ocf_core_stats_core_error_update(req->core, OCF_WRITE);
	}

	_ocf_write_wt_req_complete(req);
}

static inline void _ocf_write_wt_submit(struct ocf_request *req)
{
	/* Submit IOs */
	OCF_DEBUG_RQ(req, "Submit");

	env_atomic_set(&req->req_remaining, 2); /* cache IO + core IO */

	/* To cache */
	ocf_engine_forward_cache_io_req(req, OCF_WRITE,
			_ocf_write_wt_cache_complete);

	/* To core */
	ocf_engine_forward_core_io_req(req, _ocf_write_wt_core_complete);
}

static int _ocf_write_wt_do(struct ocf_request *req)
{
	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	if (!req->info.dirty_any) {
		/* Set metadata bits before the request submission only if the dirty
		   status for any of the request's cachelines won't change */
		_ocf_write_wt_update_bits(req);
		ENV_BUG_ON(req->info.flush_metadata);
	}

	/* Submit IO */
	_ocf_write_wt_submit(req);

	/* Update statistics */
	ocf_engine_update_request_stats(req);
	ocf_engine_update_block_stats(req);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}

static const struct ocf_engine_callbacks _wt_engine_callbacks =
{
	.resume = ocf_engine_on_resume,
};

int ocf_write_wt(struct ocf_request *req)
{
	int lock = OCF_LOCK_NOT_ACQUIRED;


	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	/* Set resume handler */
	req->engine_handler = _ocf_write_wt_do;
	req->engine_cbs = &_wt_engine_callbacks;

	lock = ocf_engine_prepare_clines(req);

	if (!ocf_req_test_mapping_error(req)) {
		if (lock >= 0) {
			if (lock != OCF_LOCK_ACQUIRED) {
				/* WR lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(req, "NO LOCK");
			} else {
				_ocf_write_wt_do(req);
			}
		} else {
			OCF_DEBUG_RQ(req, "LOCK ERROR %d\n", lock);
			req->complete(req, lock);
			ocf_req_put(req);
		}
	} else {
		ocf_req_clear(req);
		ocf_write_wi(req);
	}

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}
