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
#include "../utils/utils_rq.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_part.h"
#include "../metadata/metadata.h"
#include "../ocf_def_priv.h"

#define OCF_ENGINE_DEBUG_IO_NAME "rd"
#include "engine_debug.h"

static void _ocf_read_generic_hit_io(void *private_data, int error)
{
	struct ocf_request *rq = private_data;

	if (error)
		rq->error |= error;

	if (rq->error)
		inc_fallback_pt_error_counter(rq->cache);

	/* Handle callback-caller race to let only one of the two complete the
	 * request. Also, complete original request only if this is the last
	 * sub-request to complete
	 */
	if (env_atomic_dec_return(&rq->req_remaining) == 0) {
		OCF_DEBUG_RQ(rq, "HIT completion");

		if (rq->error) {
			env_atomic_inc(&rq->cache->core_obj[rq->core_id].
				counters->cache_errors.read);
			ocf_engine_push_rq_front_pt(rq);
		} else {

			ocf_rq_unlock(rq);

			/* Complete request */
			rq->complete(rq, rq->error);

			/* Free the request at the last point
			 * of the completion path
			 */
			ocf_rq_put(rq);
		}
	}
}

static void _ocf_read_generic_miss_io(void *private_data, int error)
{
	struct ocf_request *rq = private_data;
	struct ocf_cache *cache = rq->cache;

	if (error)
		rq->error = error;

	/* Handle callback-caller race to let only one of the two complete the
	 * request. Also, complete original request only if this is the last
	 * sub-request to complete
	 */
	if (env_atomic_dec_return(&rq->req_remaining) == 0) {
		OCF_DEBUG_RQ(rq, "MISS completion");

		if (rq->error) {
			/*
			 * --- Do not submit this request to write-back-thread.
			 * Stop it here ---
			 */
			rq->complete(rq, rq->error);

			rq->info.core_error = 1;
			env_atomic_inc(&cache->core_obj[rq->core_id].
					counters->core_errors.read);

			ctx_data_free(cache->owner, rq->cp_data);
			rq->cp_data = NULL;

			/* Invalidate metadata */
			ocf_engine_invalidate(rq);

			return;
		}

		/* Copy pages to copy vec, since this is the one needed
		 * by the above layer
		 */
		ctx_data_cpy(cache->owner, rq->cp_data, rq->data, 0, 0,
				rq->byte_length);

		/* Complete request */
		rq->complete(rq, rq->error);

		ocf_engine_backfill(rq);
	}
}

static inline void _ocf_read_generic_submit_hit(struct ocf_request *rq)
{
	env_atomic_set(&rq->req_remaining, ocf_engine_io_count(rq));

	ocf_submit_cache_reqs(rq->cache, rq->map, rq, OCF_READ,
		ocf_engine_io_count(rq), _ocf_read_generic_hit_io, rq);
}

static inline void _ocf_read_generic_submit_miss(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;
	int ret;

	env_atomic_set(&rq->req_remaining, 1);

	rq->cp_data = ctx_data_alloc(cache->owner,
			BYTES_TO_PAGES(rq->byte_length));
	if (!rq->cp_data)
		goto err_alloc;

	ret = ctx_data_mlock(cache->owner, rq->cp_data);
	if (ret)
		goto err_alloc;

	/* Submit read request to core device. */
	ocf_submit_obj_req(&cache->core_obj[rq->core_id].obj, rq, OCF_READ,
			_ocf_read_generic_miss_io, rq);

	return;

err_alloc:
	_ocf_read_generic_miss_io(rq, -ENOMEM);
}

static int _ocf_read_generic_do(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	if (ocf_engine_is_miss(rq) && rq->map->rd_locked) {
		/* Miss can be handled only on write locks.
		 * Need to switch to PT
		 */
		OCF_DEBUG_RQ(rq, "Switching to PT");
		ocf_read_pt_do(rq);
		return 0;
	}

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	if (ocf_engine_is_miss(rq)) {
		if (rq->info.dirty_any) {
			OCF_METADATA_LOCK_RD();

			/* Request is dirty need to clean request */
			ocf_engine_clean(rq);

			OCF_METADATA_UNLOCK_RD();

			/* We need to clean request before processing, return */
			ocf_rq_put(rq);

			return 0;
		}

		OCF_METADATA_LOCK_RD();

		/* Set valid status bits map */
		ocf_set_valid_map_info(rq);

		OCF_METADATA_UNLOCK_RD();
	}

	if (rq->info.re_part) {
		OCF_DEBUG_RQ(rq, "Re-Part");

		OCF_METADATA_LOCK_WR();

		/* Probably some cache lines are assigned into wrong
		 * partition. Need to move it to new one
		 */
		ocf_part_move(rq);

		OCF_METADATA_UNLOCK_WR();
	}

	OCF_DEBUG_RQ(rq, "Submit");

	/* Submit IO */
	if (ocf_engine_is_hit(rq))
		_ocf_read_generic_submit_hit(rq);
	else
		_ocf_read_generic_submit_miss(rq);

	/* Updata statistics */
	ocf_engine_update_request_stats(rq);
	ocf_engine_update_block_stats(rq);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}

static const struct ocf_io_if _io_if_read_generic_resume = {
		.read = _ocf_read_generic_do,
		.write = _ocf_read_generic_do,
};

int ocf_read_generic(struct ocf_request *rq)
{
	bool mapped;
	int lock = OCF_LOCK_NOT_ACQUIRED;
	struct ocf_cache *cache = rq->cache;

	ocf_io_start(rq->io);

	if (env_atomic_read(&cache->pending_read_misses_list_blocked)) {
		/* There are conditions to bypass IO */
		ocf_get_io_if(ocf_cache_mode_pt)->read(rq);
		return 0;
	}

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* Set resume call backs */
	rq->resume = ocf_engine_on_resume;
	rq->io_if = &_io_if_read_generic_resume;

	/*- Metadata RD access -----------------------------------------------*/

	OCF_METADATA_LOCK_RD();

	/* Traverse request to cache if there is hit */
	ocf_engine_traverse(rq);

	mapped = ocf_engine_is_mapped(rq);
	if (mapped) {
		/* Request is fully mapped, no need to call eviction */
		if (ocf_engine_is_hit(rq)) {
			/* There is a hit, lock request for READ access */
			lock = ocf_rq_trylock_rd(rq);
		} else {
			/* All cache line mapped, but some sectors are not valid
			 * and cache insert will be performed - lock for
			 * WRITE is required
			 */
			lock = ocf_rq_trylock_wr(rq);
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
		ocf_engine_map(rq);

		if (!rq->info.eviction_error) {
			if (ocf_engine_is_hit(rq)) {
				/* After mapping turns out there is hit,
				 * so lock OCF request for read access
				 */
				lock = ocf_rq_trylock_rd(rq);
			} else {
				/* Miss, new cache lines were mapped,
				 * need to lock OCF request for write access
				 */
				lock = ocf_rq_trylock_wr(rq);
			}
		}
		OCF_METADATA_UNLOCK_WR();

		/*- END Metadata WR access -----------------------------------*/
	}

	if (!rq->info.eviction_error) {
		if (lock >= 0) {
			if (lock != OCF_LOCK_ACQUIRED) {
				/* Lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(rq, "NO LOCK");
			} else {
				/* Lock was acquired can perform IO */
				_ocf_read_generic_do(rq);
			}
		} else {
			OCF_DEBUG_RQ(rq, "LOCK ERROR %d", lock);
			rq->complete(rq, lock);
			ocf_rq_put(rq);
		}
	} else {
		ocf_rq_clear(rq);
		ocf_get_io_if(ocf_cache_mode_pt)->read(rq);
	}


	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}
