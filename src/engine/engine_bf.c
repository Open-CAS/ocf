/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024-2025 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "../ocf_ctx_priv.h"
#include "engine_bf.h"
#include "engine_inv.h"
#include "engine_common.h"
#include "engine_io.h"
#include "cache_engine.h"
#include "../ocf_request.h"
#include "../concurrency/ocf_concurrency.h"
#include "../utils/utils_io.h"

#define OCF_ENGINE_DEBUG_IO_NAME "bf"
#include "engine_debug.h"

/* Decrements and checks if queue may be unblocked again */
static inline void backfill_queue_dec_unblock(struct ocf_cache *cache)
{
	env_atomic_dec(&cache->pending_read_misses_list_count);

	if (!env_atomic_read(&cache->pending_read_misses_list_blocked))
		return;

	if (env_atomic_read(&cache->pending_read_misses_list_count)
			< cache->backfill.queue_unblock_size)
		env_atomic_set(&cache->pending_read_misses_list_blocked, 0);
}

static inline void backfill_queue_inc_block(struct ocf_cache *cache)
{
	if (env_atomic_inc_return(&cache->pending_read_misses_list_count)
			>= cache->backfill.max_queue_size)
		env_atomic_set(&cache->pending_read_misses_list_blocked, 1);
}

static int _ocf_backfill_update_metadata(struct ocf_request *req)
{
	ocf_cache_t cache = req->cache;

	ocf_hb_req_prot_lock_wr(req);

	ocf_set_valid_map_info(req);

	ocf_hb_req_prot_unlock_wr(req);

	ocf_req_unlock(ocf_cache_line_concurrency(cache), req);

	ocf_req_put(req);

	return 0;
}

static void _ocf_backfill_complete(struct ocf_request *req, int error)
{
	struct ocf_cache *cache = req->cache;

	if (error) {
		ocf_core_stats_cache_error_update(req->core, OCF_WRITE);
		inc_fallback_pt_error_counter(req->cache);
	}

	backfill_queue_dec_unblock(req->cache);

	/* We must free the pages we have allocated */
	if (likely(req->data)) {
		ctx_data_secure_erase(cache->owner, req->data);
		ctx_data_munlock(cache->owner, req->data);
		ctx_data_free(cache->owner, req->data);
		req->data = NULL;
	}

	if (error) {
		ocf_engine_invalidate(req);
	} else {
		ocf_queue_push_req_cb(req, _ocf_backfill_update_metadata,
				OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
	}
}

static int _ocf_backfill_do(struct ocf_request *req)
{
	req->data = req->cp_data;
	if (unlikely(req->data == NULL)) {
		_ocf_backfill_complete(req, -OCF_ERR_NO_MEM);
		return 0;
	}

	ocf_engine_forward_cache_io_req(req, OCF_WRITE, _ocf_backfill_complete);

	return 0;
}

void ocf_engine_backfill(struct ocf_request *req)
{
	backfill_queue_inc_block(req->cache);
	ocf_queue_push_req_cb(req, _ocf_backfill_do,
			OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}
