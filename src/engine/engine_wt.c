/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_wt.h"
#include "engine_inv.h"
#include "engine_common.h"
#include "../utils/utils_req.h"
#include "../utils/utils_io.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_part.h"
#include "../metadata/metadata.h"
#include "../concurrency/ocf_concurrency.h"

#define OCF_ENGINE_DEBUG_IO_NAME "wt"
#include "engine_debug.h"

static void _ocf_write_wt_req_complete(struct ocf_request *req)
{
	if (env_atomic_dec_return(&req->req_remaining))
		return;

	OCF_DEBUG_RQ(req, "Completion");

	if (req->error) {
		/* An error occured */

		/* Complete request */
		req->complete(req, req->info.core_error ? req->error : 0);

		ocf_engine_invalidate(req);
	} else {
		/* Unlock reqest from WRITE access */
		ocf_req_unlock_wr(req);

		/* Complete request */
		req->complete(req, req->info.core_error ? req->error : 0);

		/* Release OCF request */
		ocf_req_put(req);
	}
}

static void _ocf_write_wt_cache_complete(struct ocf_request *req, int error)
{
	if (error) {
		req->error = req->error ?: error;
		env_atomic_inc(&req->cache->core[req->core_id].counters->
				cache_errors.write);

		if (req->error)
			inc_fallback_pt_error_counter(req->cache);
	}

	_ocf_write_wt_req_complete(req);
}

static void _ocf_write_wt_core_complete(struct ocf_request *req, int error)
{
	if (error) {
		req->error = error;
		req->info.core_error = 1;
		env_atomic_inc(&req->cache->core[req->core_id].counters->
				core_errors.write);
	}

	_ocf_write_wt_req_complete(req);
}

static inline void _ocf_write_wt_submit(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	/* Submit IOs */
	OCF_DEBUG_RQ(req, "Submit");

	/* Calculate how many IOs need to be submited */
	env_atomic_set(&req->req_remaining, ocf_engine_io_count(req)); /* Cache IO */
	env_atomic_inc(&req->req_remaining); /* Core device IO */

	if (req->info.flush_metadata) {
		/* Metadata flush IO */

		ocf_metadata_flush_do_asynch(cache, req,
				_ocf_write_wt_cache_complete);
	}

	/* To cache */
	ocf_submit_cache_reqs(cache, req->map, req, OCF_WRITE,
			ocf_engine_io_count(req), _ocf_write_wt_cache_complete);

	/* To core */
	ocf_submit_obj_req(&cache->core[req->core_id].obj, req,
			_ocf_write_wt_core_complete);
}

static void _ocf_write_wt_update_bits(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	if (ocf_engine_is_miss(req)) {
		OCF_METADATA_LOCK_RD();

		/* Update valid status bits */
		ocf_set_valid_map_info(req);

		OCF_METADATA_UNLOCK_RD();
	}

	if (req->info.dirty_any) {
		OCF_METADATA_LOCK_WR();

		/* Writes goes to SDD and HDD, need to update status bits from
		 * dirty to clean
		 */

		ocf_set_clean_map_info(req);

		OCF_METADATA_UNLOCK_WR();
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
}

static int _ocf_write_wt_do(struct ocf_request *req)
{
	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	/* Update status bits */
	_ocf_write_wt_update_bits(req);

	/* Submit IO */
	_ocf_write_wt_submit(req);

	/* Updata statistics */
	ocf_engine_update_request_stats(req);
	ocf_engine_update_block_stats(req);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}

static const struct ocf_io_if _io_if_wt_resume = {
		.read = _ocf_write_wt_do,
		.write = _ocf_write_wt_do,
};

int ocf_write_wt(struct ocf_request *req)
{
	bool mapped;
	int lock = OCF_LOCK_NOT_ACQUIRED;
	struct ocf_cache *cache = req->cache;

	ocf_io_start(req->io);

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	/* Set resume call backs */
	req->resume = ocf_engine_on_resume;
	req->io_if = &_io_if_wt_resume;

	OCF_METADATA_LOCK_RD(); /*- Metadata READ access, No eviction --------*/

	/* Travers to check if request is mapped fully */
	ocf_engine_traverse(req);

	mapped = ocf_engine_is_mapped(req);
	if (mapped) {
		/* All cache line are mapped, lock request for WRITE access */
		lock = ocf_req_trylock_wr(req);
	}

	OCF_METADATA_UNLOCK_RD(); /*- END Metadata READ access----------------*/

	if (!mapped) {
		OCF_METADATA_LOCK_WR(); /*- Metadata WR access, eviction -----*/

		/* Now there is exclusive access for metadata. May traverse once
		 * again. If there are misses need to call eviction. This
		 * process is called 'mapping'.
		 */
		ocf_engine_map(req);

		if (!req->info.eviction_error) {
			/* Lock request for WRITE access */
			lock = ocf_req_trylock_wr(req);
		}

		OCF_METADATA_UNLOCK_WR(); /*- END Metadata WR access ---------*/
	}

	if (!req->info.eviction_error) {
		if (lock >= 0) {
			if (lock != OCF_LOCK_ACQUIRED) {
				/* WR lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(req, "NO LOCK");
			} else {
				_ocf_write_wt_do(req);
			}
		} else {
			OCF_DEBUG_RQ(req, "LOCK ERROR %d\n", lock);
			req->complete(req, lock);
			ocf_req_put(req);
		}
	} else {
		ocf_req_clear(req);
		ocf_get_io_if(ocf_cache_mode_pt)->write(req);
	}

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}
