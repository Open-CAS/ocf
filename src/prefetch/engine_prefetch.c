/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "engine_prefetch.h"
#include "../ocf_cache_priv.h"
#include "../engine/engine_inv.h"
#include "../engine/engine_bf.h"
#include "../engine/engine_common.h"
#include "../engine/engine_io.h"
#include "../concurrency/ocf_concurrency.h"
#include "../ocf_request.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_user_part.h"
#include "../metadata/metadata.h"
#include "../ocf_def_priv.h"
#include "ocf/ocf_blktrace.h"

#define OCF_ENGINE_DEBUG_IO_NAME "prefetch"
#include "../engine/engine_debug.h"

static void _ocf_prefetch_read_complete(struct ocf_request *req, int error)
{
	OCF_DEBUG_RQ(req, "Prefetch read completion");

	ocf_req_get(req);

	if (error) {
		req->complete(req, error);

		ctx_data_free(req->cache->owner, req->data);

		ocf_core_stats_core_error_update(req->core, OCF_READ);

		/* Invalidate metadata */
		ocf_engine_invalidate(req);

		return;
	}

	/* Pretend the data is the copy, so that it's used by the backfill */
	req->cp_data = req->data;
	req->data = NULL;

	/* Complete request */
	req->complete(req, error);

	ocf_engine_backfill(req);
}

static int _ocf_prefetch_read_do(struct ocf_request *req)
{
	struct ocf_alock *c = ocf_cache_line_concurrency(req->cache);

	if (unlikely(ocf_engine_is_hit(req))) {
		ocf_req_unlock(c, req);
		req->complete(req, 0);
		return 0;
	}

	if (req->info.dirty_any) {
		ocf_hb_req_prot_lock_rd(req);

		/* Request is dirty need to clean request */
		ocf_engine_clean(req);

		ocf_hb_req_prot_unlock_rd(req);
		return 0;
	}

	req->data = ctx_data_alloc(ocf_cache_get_ctx(req->cache),
			OCF_DIV_ROUND_UP(req->bytes, PAGE_SIZE));
	if (!req->data) {
		ocf_req_unlock(c, req);
		req->complete(req, 0);
		return 0;
	}

	ocf_hb_req_prot_lock_wr(req);

	/* Set valid status bits map */
	ocf_set_valid_map_info(req);

	if (ocf_engine_needs_repart(req)) {
		OCF_DEBUG_RQ(req, "Re-Part");

		/* Probably some cache lines are assigned into wrong
		 * partition. Need to move it to new one
		 */
		ocf_user_part_move(req);
	}

	ocf_hb_req_prot_unlock_wr(req);

	OCF_DEBUG_RQ(req, "Submit");

	ocf_req_get(req);
	ocf_engine_forward_core_io_req(req, _ocf_prefetch_read_complete);

	/* Update statistics */
	ocf_engine_update_request_stats(req);
	ocf_req_put(req);

	return 0;
}

int ocf_prefetch_read(struct ocf_request *req)
{
	struct ocf_user_part *user_part = &req->cache->user_parts[req->part_id];
	struct ocf_alock *c = ocf_cache_line_concurrency(req->cache);
	ocf_cache_t cache = req->cache;
	int lock;

	if (env_atomic_read(&cache->pending_read_misses_list_blocked)) {
		req->complete(req, -OCF_ERR_BUSY);
		return 0;
	}

	req->engine_handler = _ocf_prefetch_read_do;

	if (!ocf_user_part_is_enabled(user_part)) {
		req->complete(req, -OCF_ERR_BUSY);
		return 0;
	}

	ocf_req_hash(req);

	ocf_hb_req_prot_lock_wr(req);

	ocf_engine_lookup(req);

	if (unlikely(ocf_engine_is_hit(req))) {
		ocf_hb_req_prot_unlock_wr(req);
		req->complete(req, 0);
		return 0;
	}

	ocf_prepare_clines_miss(req);
	if (unlikely(ocf_req_test_mapping_error(req))) {
		ocf_hb_req_prot_unlock_wr(req);
		req->complete(req, 0);
		return 0;
	}

	lock = ocf_req_async_lock_wr(c, req, ocf_engine_on_resume);
	if (unlikely(lock < 0)) {
		ocf_hb_req_prot_unlock_wr(req);
		req->complete(req, 0);
		return 0;
	}

	ocf_hb_req_prot_unlock_wr(req);

	if (lock == OCF_LOCK_ACQUIRED)
		_ocf_prefetch_read_do(req);

	return 0;
}
