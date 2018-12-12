/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_wt.h"
#include "engine_inv.h"
#include "engine_common.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_io.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_part.h"
#include "../metadata/metadata.h"
#include "../concurrency/ocf_concurrency.h"

#define OCF_ENGINE_DEBUG_IO_NAME "wt"
#include "engine_debug.h"

static void _ocf_write_wt_io(struct ocf_request *rq)
{
	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	OCF_DEBUG_RQ(rq, "Completion");

	if (rq->error) {
		/* An error occured */

		/* Complete request */
		rq->complete(rq, rq->info.core_error ? rq->error : 0);

		ocf_engine_invalidate(rq);
	} else {
		/* Unlock reqest from WRITE access */
		ocf_rq_unlock_wr(rq);

		/* Complete request */
		rq->complete(rq, rq->info.core_error ? rq->error : 0);

		/* Release OCF request */
		ocf_rq_put(rq);
	}
}

static void _ocf_write_wt_cache_io(struct ocf_request *rq, int error)
{
	if (error) {
		rq->error = rq->error ?: error;
		env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				cache_errors.write);

		if (rq->error)
			inc_fallback_pt_error_counter(rq->cache);
	}

	_ocf_write_wt_io(rq);
}

static void _ocf_write_wt_core_io(struct ocf_request *rq, int error)
{
	if (error) {
		rq->error = error;
		rq->info.core_error = 1;
		env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				core_errors.write);
	}

	_ocf_write_wt_io(rq);
}

static inline void _ocf_write_wt_submit(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	/* Submit IOs */
	OCF_DEBUG_RQ(rq, "Submit");

	/* Calculate how many IOs need to be submited */
	env_atomic_set(&rq->req_remaining, ocf_engine_io_count(rq)); /* Cache IO */
	env_atomic_inc(&rq->req_remaining); /* Core device IO */

	if (rq->info.flush_metadata) {
		/* Metadata flush IO */

		ocf_metadata_flush_do_asynch(cache, rq,
				_ocf_write_wt_cache_io);
	}

	/* To cache */
	ocf_submit_cache_reqs(cache, rq->map, rq, OCF_WRITE,
			ocf_engine_io_count(rq), _ocf_write_wt_cache_io);

	/* To core */
	ocf_submit_obj_req(&cache->core_obj[rq->core_id].obj, rq,
			_ocf_write_wt_core_io);
}

static void _ocf_write_wt_update_bits(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	if (ocf_engine_is_miss(rq)) {
		OCF_METADATA_LOCK_RD();

		/* Update valid status bits */
		ocf_set_valid_map_info(rq);

		OCF_METADATA_UNLOCK_RD();
	}

	if (rq->info.dirty_any) {
		OCF_METADATA_LOCK_WR();

		/* Writes goes to SDD and HDD, need to update status bits from
		 * dirty to clean
		 */

		ocf_set_clean_map_info(rq);

		OCF_METADATA_UNLOCK_WR();
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
}

static int _ocf_write_wt_do(struct ocf_request *rq)
{
	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* Update status bits */
	_ocf_write_wt_update_bits(rq);

	/* Submit IO */
	_ocf_write_wt_submit(rq);

	/* Updata statistics */
	ocf_engine_update_request_stats(rq);
	ocf_engine_update_block_stats(rq);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}

static const struct ocf_io_if _io_if_wt_resume = {
		.read = _ocf_write_wt_do,
		.write = _ocf_write_wt_do,
};

int ocf_write_wt(struct ocf_request *rq)
{
	bool mapped;
	int lock = OCF_LOCK_NOT_ACQUIRED;
	struct ocf_cache *cache = rq->cache;

	ocf_io_start(rq->io);

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* Set resume call backs */
	rq->resume = ocf_engine_on_resume;
	rq->io_if = &_io_if_wt_resume;

	OCF_METADATA_LOCK_RD(); /*- Metadata READ access, No eviction --------*/

	/* Travers to check if request is mapped fully */
	ocf_engine_traverse(rq);

	mapped = ocf_engine_is_mapped(rq);
	if (mapped) {
		/* All cache line are mapped, lock request for WRITE access */
		lock = ocf_rq_trylock_wr(rq);
	}

	OCF_METADATA_UNLOCK_RD(); /*- END Metadata READ access----------------*/

	if (!mapped) {
		OCF_METADATA_LOCK_WR(); /*- Metadata WR access, eviction -----*/

		/* Now there is exclusive access for metadata. May traverse once
		 * again. If there are misses need to call eviction. This
		 * process is called 'mapping'.
		 */
		ocf_engine_map(rq);

		if (!rq->info.eviction_error) {
			/* Lock request for WRITE access */
			lock = ocf_rq_trylock_wr(rq);
		}

		OCF_METADATA_UNLOCK_WR(); /*- END Metadata WR access ---------*/
	}

	if (!rq->info.eviction_error) {
		if (lock >= 0) {
			if (lock != OCF_LOCK_ACQUIRED) {
				/* WR lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(rq, "NO LOCK");
			} else {
				_ocf_write_wt_do(rq);
			}
		} else {
			OCF_DEBUG_RQ(rq, "LOCK ERROR %d\n", lock);
			rq->complete(rq, lock);
			ocf_rq_put(rq);
		}
	} else {
		ocf_rq_clear(rq);
		ocf_get_io_if(ocf_cache_mode_pt)->write(rq);
	}

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}
