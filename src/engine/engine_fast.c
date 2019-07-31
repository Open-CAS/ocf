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
#include "../ocf_request.h"
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

static void _ocf_read_fast_complete(struct ocf_request *req, int error)
{
	if (error)
		req->error |= error;

	if (env_atomic_dec_return(&req->req_remaining)) {
		/* Not all requests finished */
		return;
	}

	OCF_DEBUG_RQ(req, "HIT completion");

	if (req->error) {
		OCF_DEBUG_RQ(req, "ERROR");

		ocf_core_stats_cache_error_update(req->core, OCF_READ);
		ocf_engine_push_req_front_pt(req);
	} else {
		ocf_req_unlock(req);

		/* Complete request */
		req->complete(req, req->error);

		/* Free the request at the last point of the completion path */
		ocf_req_put(req);
	}
}

static int _ocf_read_fast_do(struct ocf_request *req)
{
	if (ocf_engine_is_miss(req)) {
		/* It seams that after resume, now request is MISS, do PT */
		OCF_DEBUG_RQ(req, "Switching to read PT");
		ocf_read_pt_do(req);
		return 0;

	}

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	if (req->info.re_part) {
		OCF_DEBUG_RQ(req, "Re-Part");

		ocf_req_hash_lock_wr(req);

		/* Probably some cache lines are assigned into wrong
		 * partition. Need to move it to new one
		 */
		ocf_part_move(req);

		ocf_req_hash_unlock_wr(req);
	}

	/* Submit IO */
	OCF_DEBUG_RQ(req, "Submit");
	env_atomic_set(&req->req_remaining, ocf_engine_io_count(req));
	ocf_submit_cache_reqs(req->cache, req, OCF_READ, 0, req->byte_length,
		ocf_engine_io_count(req), _ocf_read_fast_complete);


	/* Update statistics */
	ocf_engine_update_request_stats(req);
	ocf_engine_update_block_stats(req);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}

static const struct ocf_io_if _io_if_read_fast_resume = {
	.read = _ocf_read_fast_do,
	.write = _ocf_read_fast_do,
};

int ocf_read_fast(struct ocf_request *req)
{
	bool hit;
	int lock = OCF_LOCK_NOT_ACQUIRED;

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	/* Set resume io_if */
	req->io_if = &_io_if_read_fast_resume;

	/*- Metadata RD access -----------------------------------------------*/

	ocf_req_hash(req);
	ocf_req_hash_lock_rd(req);

	/* Traverse request to cache if there is hit */
	ocf_engine_traverse(req);

	hit = ocf_engine_is_hit(req);
	if (hit) {
		ocf_io_start(&req->ioi.io);
		lock = ocf_req_async_lock_rd(req, ocf_engine_on_resume);
	}

	ocf_req_hash_unlock_rd(req);

	if (hit) {
		OCF_DEBUG_RQ(req, "Fast path success");

		if (lock >= 0) {
			if (lock != OCF_LOCK_ACQUIRED) {
				/* Lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(req, "NO LOCK");
			} else {
				/* Lock was acquired can perform IO */
				_ocf_read_fast_do(req);
			}
		} else {
			OCF_DEBUG_RQ(req, "LOCK ERROR");
			req->complete(req, lock);
			ocf_req_put(req);
		}
	} else {
		OCF_DEBUG_RQ(req, "Fast path failure");
	}

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

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

int ocf_write_fast(struct ocf_request *req)
{
	bool mapped;
	int lock = OCF_LOCK_NOT_ACQUIRED;

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	/* Set resume io_if */
	req->io_if = &_io_if_write_fast_resume;

	/*- Metadata RD access -----------------------------------------------*/

	ocf_req_hash(req);
	ocf_req_hash_lock_rd(req);

	/* Traverse request to cache if there is hit */
	ocf_engine_traverse(req);

	mapped = ocf_engine_is_mapped(req);
	if (mapped) {
		ocf_io_start(&req->ioi.io);
		lock = ocf_req_async_lock_wr(req, ocf_engine_on_resume);
	}

	ocf_req_hash_unlock_rd(req);

	if (mapped) {
		if (lock >= 0) {
			OCF_DEBUG_RQ(req, "Fast path success");

			if (lock != OCF_LOCK_ACQUIRED) {
				/* Lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(req, "NO LOCK");
			} else {
				/* Lock was acquired can perform IO */
				ocf_write_wb_do(req);
			}
		} else {
			OCF_DEBUG_RQ(req, "Fast path lock failure");
			req->complete(req, lock);
			ocf_req_put(req);
		}
	} else {
		OCF_DEBUG_RQ(req, "Fast path failure");
	}

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return mapped ? OCF_FAST_PATH_YES : OCF_FAST_PATH_NO;

}
