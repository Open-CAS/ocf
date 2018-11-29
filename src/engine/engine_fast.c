/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_fast.h"
#include "engine_common.h"
#include "engine_pt.h"
#include "engine_wb.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_part.h"
#include "../utils/utils_io.h"
#include "../concurrency/ocf_concurrency.h"
#include "../metadata/metadata.h"

#define OCF_ENGINE_DEBUG 0

#define OCF_ENGINE_DEBUG_IO_NAME "fast"
#include "engine_debug.h"

/*    _____                _   ______        _     _____      _   _
 *   |  __ \              | | |  ____|      | |   |  __ \    | | | |
 *   | |__) |___  __ _  __| | | |__ __ _ ___| |_  | |__) |_ _| |_| |__
 *   |  _  // _ \/ _` |/ _` | |  __/ _` / __| __| |  ___/ _` | __| '_ \
 *   | | \ \  __/ (_| | (_| | | | | (_| \__ \ |_  | |  | (_| | |_| | | |
 *   |_|  \_\___|\__,_|\__,_| |_|  \__,_|___/\__| |_|   \__,_|\__|_| |_|
 */

static void _ocf_read_fast_io(void *private_data, int error)
{
	struct ocf_request *rq = private_data;

	if (error)
		rq->error |= error;

	if (env_atomic_dec_return(&rq->req_remaining)) {
		/* Not all requests finished */
		return;
	}

	OCF_DEBUG_RQ(rq, "HIT completion");

	if (rq->error) {
		OCF_DEBUG_RQ(rq, "ERROR");

		env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				cache_errors.read);
		ocf_engine_push_rq_front_pt(rq);
	} else {
		ocf_rq_unlock(rq);

		/* Complete request */
		rq->complete(rq, rq->error);

		/* Free the request at the last point of the completion path */
		ocf_rq_put(rq);
	}
}

static int _ocf_read_fast_do(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	if (ocf_engine_is_miss(rq)) {
		/* It seams that after resume, now request is MISS, do PT */
		OCF_DEBUG_RQ(rq, "Switching to read PT");
		ocf_read_pt_do(rq);
		return 0;

	}

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	if (rq->info.re_part) {
		OCF_DEBUG_RQ(rq, "Re-Part");

		OCF_METADATA_LOCK_WR();

		/* Probably some cache lines are assigned into wrong
		 * partition. Need to move it to new one
		 */
		ocf_part_move(rq);

		OCF_METADATA_UNLOCK_WR();
	}

	/* Submit IO */
	OCF_DEBUG_RQ(rq, "Submit");
	env_atomic_set(&rq->req_remaining, ocf_engine_io_count(rq));
	ocf_submit_cache_reqs(rq->cache, rq->map, rq, OCF_READ,
		ocf_engine_io_count(rq), _ocf_read_fast_io, rq);


	/* Updata statistics */
	ocf_engine_update_request_stats(rq);
	ocf_engine_update_block_stats(rq);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}

static const struct ocf_io_if _io_if_read_fast_resume = {
		.read = _ocf_read_fast_do,
		.write = _ocf_read_fast_do,
};

int ocf_read_fast(struct ocf_request *rq)
{
	bool hit;
	int lock = OCF_LOCK_NOT_ACQUIRED;
	struct ocf_cache *cache = rq->cache;

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* Set resume call backs */
	rq->resume = ocf_engine_on_resume;
	rq->io_if = &_io_if_read_fast_resume;

	/*- Metadata RD access -----------------------------------------------*/

	OCF_METADATA_LOCK_RD();

	/* Traverse request to cache if there is hit */
	ocf_engine_traverse(rq);

	hit = ocf_engine_is_hit(rq);
	if (hit) {
		ocf_io_start(rq->io);
		lock = ocf_rq_trylock_rd(rq);
	}

	OCF_METADATA_UNLOCK_RD();

	if (hit) {
		OCF_DEBUG_RQ(rq, "Fast path success");

		if (lock >= 0) {
			if (lock != OCF_LOCK_ACQUIRED) {
				/* Lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(rq, "NO LOCK");
			} else {
				/* Lock was acquired can perform IO */
				_ocf_read_fast_do(rq);
			}
		} else {
			OCF_DEBUG_RQ(rq, "LOCK ERROR");
			rq->complete(rq, lock);
			ocf_rq_put(rq);
		}
	} else {
		OCF_DEBUG_RQ(rq, "Fast path failure");
	}

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	if (hit)
		return OCF_FAST_PATH_YES;
	else
		return OCF_FAST_PATH_NO;
}

/*  __          __   _ _         ______        _     _____      _   _
 *  \ \        / /  (_) |       |  ____|      | |   |  __ \    | | | |
 *   \ \  /\  / / __ _| |_ ___  | |__ __ _ ___| |_  | |__) |_ _| |_| |__
 *    \ \/  \/ / '__| | __/ _ \ |  __/ _` / __| __| |  ___/ _` | __| '_ \
 *     \  /\  /| |  | | ||  __/ | | | (_| \__ \ |_  | |  | (_| | |_| | | |
 *      \/  \/ |_|  |_|\__\___| |_|  \__,_|___/\__| |_|   \__,_|\__|_| |_|
 */

static const struct ocf_io_if _io_if_write_fast_resume = {
		.read = ocf_write_wb_do,
		.write = ocf_write_wb_do,
};

int ocf_write_fast(struct ocf_request *rq)
{
	bool mapped;
	int lock = OCF_LOCK_NOT_ACQUIRED;
	struct ocf_cache *cache = rq->cache;

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* Set resume call backs */
	rq->resume = ocf_engine_on_resume;
	rq->io_if = &_io_if_write_fast_resume;

	/*- Metadata RD access -----------------------------------------------*/

	OCF_METADATA_LOCK_RD();

	/* Traverse request to cache if there is hit */
	ocf_engine_traverse(rq);

	mapped = ocf_engine_is_mapped(rq);
	if (mapped) {
		ocf_io_start(rq->io);
		lock = ocf_rq_trylock_wr(rq);
	}

	OCF_METADATA_UNLOCK_RD();

	if (mapped) {
		if (lock >= 0) {
			OCF_DEBUG_RQ(rq, "Fast path success");

			if (lock != OCF_LOCK_ACQUIRED) {
				/* Lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(rq, "NO LOCK");
			} else {
				/* Lock was acquired can perform IO */
				ocf_write_wb_do(rq);
			}
		} else {
			OCF_DEBUG_RQ(rq, "Fast path lock failure");
			rq->complete(rq, lock);
			ocf_rq_put(rq);
		}
	} else {
		OCF_DEBUG_RQ(rq, "Fast path failure");
	}

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return mapped ? OCF_FAST_PATH_YES : OCF_FAST_PATH_NO;

}
