/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_zero.h"
#include "engine_common.h"
#include "../concurrency/ocf_concurrency.h"
#include "../ocf_request.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_io.h"
#include "../metadata/metadata.h"

#define OCF_ENGINE_DEBUG_IO_NAME "zero"
#include "engine_debug.h"

static int ocf_zero_purge(struct ocf_request *req)
{
	/* There are mapped cache line, need to remove them */

	ocf_hb_req_prot_lock_wr(req); /*- Metadata WR access ---------------*/

	/* Remove mapped cache lines from metadata */
	ocf_purge_map_info(req);

	ocf_hb_req_prot_unlock_wr(req); /*- END Metadata WR access ---------*/

	ocf_req_unlock_wr(ocf_cache_line_concurrency(req->cache), req);
	req->complete(req, 0);
	ocf_req_put(req);

	return 0;
}

static void _ocf_zero_io_flush_metadata(struct ocf_request *req, int error)
{
	if (error) {
		ocf_core_stats_cache_error_update(req->core, OCF_WRITE);
		ocf_engine_error(req, true, "Failed to discard data on cache");

		ocf_req_unlock_wr(ocf_cache_line_concurrency(req->cache), req);
		req->complete(req, error);
		ocf_req_put(req);
		return;
	}

	ocf_queue_push_req_cb(req, ocf_zero_purge,
			OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

static inline void ocf_zero_map_info(struct ocf_request *req)
{
	uint32_t map_idx = 0;
	uint8_t start_bit;
	uint8_t end_bit;
	struct ocf_map_info *map = req->map;
	struct ocf_cache *cache = req->cache;
	uint32_t count = req->core_line_count;

	/* Purge range on the basis of map info
	 *
	 * | 01234567 | 01234567 | ... | 01234567 | 01234567 |
	 * | -----+++ | ++++++++ | +++ | ++++++++ | +++++--- |
	 * |   first  |          Middle           |   last   |
	 */

	for (map_idx = 0; map_idx < count; map_idx++) {
		if (map[map_idx].status == LOOKUP_MISS)
			continue;

		start_bit = 0;
		end_bit = ocf_line_end_sector(cache);

		if (map_idx == 0) {
			/* First */
			start_bit = BYTES_TO_PAGES_ROUND_DOWN(req->addr)
					% ocf_line_sectors(cache);
		}

		if (map_idx == (count - 1)) {
			/* Last */
			end_bit = BYTES_TO_PAGES_ROUND_DOWN(req->addr +
					req->bytes - 1) %
					ocf_line_sectors(cache);
		}

		ocf_metadata_flush_mark(cache, req, map_idx, INVALID,
				start_bit, end_bit);
	}
}

static int _ocf_zero_do(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	/* Mark cache lines for zeroing/discarding */
	ocf_zero_map_info(req);

	/* Discard marked cache lines */
	env_atomic_set(&req->req_remaining, 1);
	if (req->info.flush_metadata) {
		/* Request was dirty and need to flush metadata */
		ocf_metadata_flush_do_asynch(cache, req,
		                _ocf_zero_io_flush_metadata);
	}
	_ocf_zero_io_flush_metadata(req, 0);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}

/**
 * @note
 *	- Caller has to have metadata write lock
 *	- Core line has to be mapped
 */
void ocf_engine_zero_line(struct ocf_request *req)
{
	int lock = OCF_LOCK_NOT_ACQUIRED;

	ENV_BUG_ON(req->core_line_count != 1);

	/* No hash bucket locking here - ocf_engine_zero_line caller must hold
	 * metadata global write lock, so we have exclusive access to all hash
	 * buckets here. */

	/* Traverse to check if request is mapped */
	ocf_engine_traverse(req);

	ENV_BUG_ON(!ocf_engine_is_mapped(req));

	req->engine_handler = _ocf_zero_do;

	/* Some cache line are mapped, lock request for WRITE access */
	lock = ocf_req_async_lock_wr(
			ocf_cache_line_concurrency(req->cache),
			req, ocf_engine_on_resume);

	if (lock >= 0) {
		ENV_BUG_ON(lock != OCF_LOCK_ACQUIRED);
		ocf_queue_push_req_cb(req, _ocf_zero_do,
				OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
	} else {
		OCF_DEBUG_RQ(req, "LOCK ERROR %d", lock);
		req->complete(req, lock);
		ocf_req_put(req);
	}
}

