/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_rd.h"
#include "engine_pt.h"
#include "engine_inv.h"
#include "engine_bf.h"
#include "engine_common.h"
#include "cache_engine.h"
#include "../concurrency/ocf_concurrency.h"
#include "../utils/utils_io.h"
#include "../ocf_request.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_part.h"
#include "../metadata/metadata.h"
#include "../ocf_def_priv.h"

#define OCF_ENGINE_DEBUG_IO_NAME "rd"
#include "engine_debug.h"

static void _ocf_read_generic_hit_complete(struct ocf_request *req, int error)
{
	if (error)
		req->error |= error;

	if (req->error)
		inc_fallback_pt_error_counter(req->cache);

	/* Handle callback-caller race to let only one of the two complete the
	 * request. Also, complete original request only if this is the last
	 * sub-request to complete
	 */
	if (env_atomic_dec_return(&req->req_remaining) == 0) {
		OCF_DEBUG_RQ(req, "HIT completion");

		if (req->error) {
			env_atomic_inc(&req->core->counters->cache_errors.read);
			ocf_engine_push_req_front_pt(req);
		} else {

			ocf_req_unlock(req);

			/* Complete request */
			req->complete(req, req->error);

			/* Free the request at the last point
			 * of the completion path
			 */
			ocf_req_put(req);
		}
	}
}

static void _ocf_read_generic_miss_complete(struct ocf_request *req, int error)
{
	struct ocf_cache *cache = req->cache;

	if (error)
		req->error = error;

	/* Handle callback-caller race to let only one of the two complete the
	 * request. Also, complete original request only if this is the last
	 * sub-request to complete
	 */
	if (env_atomic_dec_return(&req->req_remaining) == 0) {
		OCF_DEBUG_RQ(req, "MISS completion");

		if (req->error) {
			/*
			 * --- Do not submit this request to write-back-thread.
			 * Stop it here ---
			 */
			req->complete(req, req->error);

			req->info.core_error = 1;
			env_atomic_inc(&req->core->counters->core_errors.read);

			ctx_data_free(cache->owner, req->cp_data);
			req->cp_data = NULL;

			/* Invalidate metadata */
			ocf_engine_invalidate(req);

			return;
		}

		/* Copy pages to copy vec, since this is the one needed
		 * by the above layer
		 */
		ctx_data_cpy(cache->owner, req->cp_data, req->data, 0, 0,
				req->byte_length);

		/* Complete request */
		req->complete(req, req->error);

		ocf_engine_backfill(req);
	}
}

static inline void _ocf_read_generic_submit_hit(struct ocf_request *req)
{
	env_atomic_set(&req->req_remaining, ocf_engine_io_count(req));

	ocf_submit_cache_reqs(req->cache, req->map, req, OCF_READ,
		ocf_engine_io_count(req), _ocf_read_generic_hit_complete);
}

static inline void _ocf_read_generic_submit_miss(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;
	int ret;

	env_atomic_set(&req->req_remaining, 1);

	req->cp_data = ctx_data_alloc(cache->owner,
			BYTES_TO_PAGES(req->byte_length));
	if (!req->cp_data)
		goto err_alloc;

	ret = ctx_data_mlock(cache->owner, req->cp_data);
	if (ret)
		goto err_alloc;

	/* Submit read request to core device. */
	ocf_submit_volume_req(&req->core->volume, req,
			_ocf_read_generic_miss_complete);

	return;

err_alloc:
	_ocf_read_generic_miss_complete(req, -OCF_ERR_NO_MEM);
}

static int _ocf_read_generic_do(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	if (ocf_engine_is_miss(req) && req->map->rd_locked) {
		/* Miss can be handled only on write locks.
		 * Need to switch to PT
		 */
		OCF_DEBUG_RQ(req, "Switching to PT");
		ocf_read_pt_do(req);
		return 0;
	}

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	if (ocf_engine_is_miss(req)) {
		if (req->info.dirty_any) {
			OCF_METADATA_LOCK_RD();

			/* Request is dirty need to clean request */
			ocf_engine_clean(req);

			OCF_METADATA_UNLOCK_RD();

			/* We need to clean request before processing, return */
			ocf_req_put(req);

			return 0;
		}

		OCF_METADATA_LOCK_RD();

		/* Set valid status bits map */
		ocf_set_valid_map_info(req);

		OCF_METADATA_UNLOCK_RD();
	}

	if (req->info.re_part) {
		OCF_DEBUG_RQ(req, "Re-Part");

		OCF_METADATA_LOCK_WR();

		/* Probably some cache lines are assigned into wrong
		 * partition. Need to move it to new one
		 */
		ocf_part_move(req);

		OCF_METADATA_UNLOCK_WR();
	}

	OCF_DEBUG_RQ(req, "Submit");

	/* Submit IO */
	if (ocf_engine_is_hit(req))
		_ocf_read_generic_submit_hit(req);
	else
		_ocf_read_generic_submit_miss(req);

	/* Updata statistics */
	ocf_engine_update_request_stats(req);
	ocf_engine_update_block_stats(req);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}

static const struct ocf_io_if _io_if_read_generic_resume = {
	.read = _ocf_read_generic_do,
	.write = _ocf_read_generic_do,
	.resume = ocf_engine_on_resume,
};

int ocf_read_generic(struct ocf_request *req)
{
	bool mapped;
	int lock = OCF_LOCK_NOT_ACQUIRED;
	struct ocf_cache *cache = req->cache;

	ocf_io_start(req->io);

	if (env_atomic_read(&cache->pending_read_misses_list_blocked)) {
		/* There are conditions to bypass IO */
		ocf_get_io_if(ocf_cache_mode_pt)->read(req);
		return 0;
	}

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	/* Set resume call backs */
	req->io_if = &_io_if_read_generic_resume;

	/*- Metadata RD access -----------------------------------------------*/

	OCF_METADATA_LOCK_RD();

	/* Traverse request to cache if there is hit */
	ocf_engine_traverse(req);

	mapped = ocf_engine_is_mapped(req);
	if (mapped) {
		/* Request is fully mapped, no need to call eviction */
		if (ocf_engine_is_hit(req)) {
			/* There is a hit, lock request for READ access */
			lock = ocf_req_trylock_rd(req);
		} else {
			/* All cache line mapped, but some sectors are not valid
			 * and cache insert will be performed - lock for
			 * WRITE is required
			 */
			lock = ocf_req_trylock_wr(req);
		}
	}

	OCF_METADATA_UNLOCK_RD();

	/*- END Metadata RD access -------------------------------------------*/

	if (!mapped) {

		/*- Metadata WR access ---------------------------------------*/

		OCF_METADATA_LOCK_WR();

		/* Now there is exclusive access for metadata. May traverse once
		 * again. If there are misses need to call eviction. This
		 * process is called 'mapping'.
		 */
		ocf_engine_map(req);

		if (!req->info.eviction_error) {
			if (ocf_engine_is_hit(req)) {
				/* After mapping turns out there is hit,
				 * so lock OCF request for read access
				 */
				lock = ocf_req_trylock_rd(req);
			} else {
				/* Miss, new cache lines were mapped,
				 * need to lock OCF request for write access
				 */
				lock = ocf_req_trylock_wr(req);
			}
		}
		OCF_METADATA_UNLOCK_WR();

		/*- END Metadata WR access -----------------------------------*/
	}

	if (!req->info.eviction_error) {
		if (lock >= 0) {
			if (lock != OCF_LOCK_ACQUIRED) {
				/* Lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(req, "NO LOCK");
			} else {
				/* Lock was acquired can perform IO */
				_ocf_read_generic_do(req);
			}
		} else {
			OCF_DEBUG_RQ(req, "LOCK ERROR %d", lock);
			req->complete(req, lock);
			ocf_req_put(req);
		}
	} else {
		ocf_req_clear(req);
		ocf_get_io_if(ocf_cache_mode_pt)->read(req);
	}


	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}
