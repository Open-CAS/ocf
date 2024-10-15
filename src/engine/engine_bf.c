/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
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
		ocf_req_unlock(ocf_cache_line_concurrency(cache), req);

		/* put the request at the last point of the completion path */
		ocf_req_put(req);
	}
}

#define __entries_not_adjacent(__req, __i, __j) \
	__req->map[__i].coll_idx + 1 != __req->map[__j].coll_idx

#define __is_the_last_chunk(__req, __i) (__i == (__req->core_line_count - 1))

#define __skip_on_the_last_entry(__skip, __req, __i) \
	__skip * (int)__is_the_last_chunk(__req, __i)

static int _ocf_backfill_do(struct ocf_request *req)
{
	ocf_cache_t cache = req->cache;
	uint64_t metadata_offset = cache->device->metadata_offset;
	ocf_cache_line_size_t cache_line_size = ocf_line_size(cache);
	uint64_t addr, bytes, total_bytes = 0;
	uint64_t seek, skip, last_chunk_size;
	uint32_t i;

	req->data = req->cp_data;
	if (unlikely(req->data == NULL)) {
		_ocf_backfill_complete(req, -OCF_ERR_NO_MEM);
		return 0;
	}

	req->cache_forward_end = _ocf_backfill_complete;

	if (ocf_engine_is_sequential(req)) {
		addr = metadata_offset;
		addr += req->map[0].coll_idx * cache_line_size;
		addr += req->addr % cache_line_size;

		ocf_core_stats_cache_block_update(req->core, req->part_id,
				OCF_WRITE, req->bytes);

		ocf_req_forward_cache_io(req, OCF_WRITE, addr, req->bytes,
				req->offset);
		return 0;
	}

	seek = req->addr % cache_line_size;
	last_chunk_size = (req->addr + req->bytes) % cache_line_size;
	skip = (cache_line_size - last_chunk_size) % cache_line_size;

	ocf_req_forward_cache_get(req);
	for (i = 0; i < req->core_line_count; i++) {
		if (req->map[i].status == LOOKUP_HIT) {
			/* This is the 1st cache line in the interval, and it's
			   a hit. Don't write it to the cache */
			total_bytes += cache_line_size;
			total_bytes -= seek;
			/* Seek should be taken into account for the first chunk
			   only */
			seek = 0;
			continue;
		}

		addr = metadata_offset;
		addr += req->map[i].coll_idx * cache_line_size;

		bytes = cache_line_size;
		for (; i < (req->core_line_count - 1); i++) {
			if (__entries_not_adjacent(req, i, i + 1))
				break;

			bytes += cache_line_size;
		}

		/* Seek should be taken into account for the first chunk only */
		addr += seek;
		bytes -= seek;
		seek = 0;

		bytes -= __skip_on_the_last_entry(skip, req, i);

		bytes = OCF_MIN(bytes, req->bytes - total_bytes);

		ocf_core_stats_cache_block_update(req->core, req->part_id,
				OCF_WRITE, bytes);

		ocf_req_forward_cache_io(req, OCF_WRITE, addr, bytes,
				req->offset + total_bytes);

		total_bytes += bytes;
	}

	ocf_req_forward_cache_put(req);

	return 0;
}

void ocf_engine_backfill(struct ocf_request *req)
{
	backfill_queue_inc_block(req->cache);
	ocf_queue_push_req_cb(req, _ocf_backfill_do,
			OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}
