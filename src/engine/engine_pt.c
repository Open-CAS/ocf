/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_pt.h"
#include "engine_common.h"
#include "cache_engine.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_io.h"
#include "../utils/utils_part.h"
#include "../metadata/metadata.h"
#include "../concurrency/ocf_concurrency.h"

#define OCF_ENGINE_DEBUG_IO_NAME "pt"
#include "engine_debug.h"

static void _ocf_read_pt_io(void *private_data, int error)
{
	struct ocf_request *rq = private_data;

	if (error)
		rq->error |= error;

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	OCF_DEBUG_RQ(rq, "Completion");

	if (rq->error) {
		rq->info.core_error = 1;
		env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				core_errors.read);
	}

	/* Complete request */
	rq->complete(rq, rq->error);

	ocf_rq_unlock_rd(rq);

	/* Release OCF request */
	ocf_rq_put(rq);
}

static inline void _ocf_read_pt_submit(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	env_atomic_set(&rq->req_remaining, 1); /* Core device IO */

	OCF_DEBUG_RQ(rq, "Submit");

	/* Core read */
	ocf_submit_obj_req(&cache->core_obj[rq->core_id].obj, rq, OCF_READ,
			_ocf_read_pt_io, rq);
}

int ocf_read_pt_do(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	if (rq->info.dirty_any) {
		OCF_METADATA_LOCK_RD();
		/* Need to clean, start it */
		ocf_engine_clean(rq);
		OCF_METADATA_UNLOCK_RD();

		/* Do not processing, because first we need to clean request */
		ocf_rq_put(rq);

		return 0;
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

	/* Submit read IO to the core */
	_ocf_read_pt_submit(rq);

	/* Update statistics */
	ocf_engine_update_block_stats(rq);
	env_atomic64_inc(&cache->core_obj[rq->core_id].counters->
			part_counters[rq->part_id].read_reqs.pass_through);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}

static const struct ocf_io_if _io_if_pt_resume = {
	.read = ocf_read_pt_do,
	.write = ocf_read_pt_do,
};

int ocf_read_pt(struct ocf_request *rq)
{
	bool use_cache = false;
	int lock = OCF_LOCK_NOT_ACQUIRED;
	struct ocf_cache *cache = rq->cache;

	OCF_DEBUG_TRACE(rq->cache);

	ocf_io_start(rq->io);

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* Set resume call backs */
	rq->resume = ocf_engine_on_resume;
	rq->io_if = &_io_if_pt_resume;

	OCF_METADATA_LOCK_RD(); /*- Metadata RD access -----------------------*/

	/* Traverse request to check if there are mapped cache lines */
	ocf_engine_traverse(rq);

	if (rq->info.seq_cutoff && ocf_engine_is_dirty_all(rq)) {
		use_cache = true;
	} else {
		if (ocf_engine_mapped_count(rq)) {
			/* There are mapped cache line,
			 * lock request for READ access
			 */
			lock = ocf_rq_trylock_rd(rq);
		} else {
			/* No mapped cache lines, no need to get lock */
			lock = OCF_LOCK_ACQUIRED;
		}
	}

	OCF_METADATA_UNLOCK_RD(); /*- END Metadata RD access -----------------*/

	if (use_cache) {
		/*
		 * There is dirt HIT, and sequential cut off,
		 * because of this force read data from cache
		 */
		ocf_rq_clear(rq);
		ocf_get_io_if(ocf_cache_mode_wt)->read(rq);
	} else {
		if (lock >= 0) {
			if (lock == OCF_LOCK_ACQUIRED) {
				/* Lock acquired perform read off operations */
				ocf_read_pt_do(rq);
			} else {
				/* WR lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(rq, "NO LOCK");
			}
		} else {
			OCF_DEBUG_RQ(rq, "LOCK ERROR %d", lock);
			rq->complete(rq, lock);
			ocf_rq_put(rq);
		}
	}

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}

void ocf_engine_push_rq_front_pt(struct ocf_request *rq)
{
	ocf_engine_push_rq_front_if(rq, &_io_if_pt_resume, true);
}

