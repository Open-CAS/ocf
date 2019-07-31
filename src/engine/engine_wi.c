/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_wi.h"
#include "engine_common.h"
#include "../concurrency/ocf_concurrency.h"
#include "../ocf_request.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_io.h"
#include "../metadata/metadata.h"

#define OCF_ENGINE_DEBUG_IO_NAME "wi"
#include "engine_debug.h"

static int ocf_write_wi_update_and_flush_metadata(struct ocf_request *req);

static const struct ocf_io_if _io_if_wi_flush_metadata = {
		.read = ocf_write_wi_update_and_flush_metadata,
		.write = ocf_write_wi_update_and_flush_metadata,
};

static void _ocf_write_wi_io_flush_metadata(struct ocf_request *req, int error)
{
	if (error) {
		ocf_core_stats_cache_error_update(req->core, OCF_WRITE);
		req->error |= error;
	}

	if (env_atomic_dec_return(&req->req_remaining))
		return;

	if (req->error)
		ocf_engine_error(req, true, "Failed to write data to cache");

	ocf_req_unlock_wr(req);

	req->complete(req, req->error);

	ocf_req_put(req);
}

static int ocf_write_wi_update_and_flush_metadata(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	env_atomic_set(&req->req_remaining, 1); /* One core IO */

	if (ocf_engine_mapped_count(req)) {
		/* There are mapped cache line, need to remove them */

		ocf_req_hash_lock_wr(req); /*- Metadata WR access ---------------*/

		/* Remove mapped cache lines from metadata */
		ocf_purge_map_info(req);

		ocf_req_hash_unlock_wr(req); /*- END Metadata WR access ---------*/

		if (req->info.flush_metadata) {
			/* Request was dirty and need to flush metadata */
			ocf_metadata_flush_do_asynch(cache, req,
					_ocf_write_wi_io_flush_metadata);
		}

	}

	_ocf_write_wi_io_flush_metadata(req, 0);

	return 0;
}

static void _ocf_write_wi_core_complete(struct ocf_request *req, int error)
{
	if (error) {
		req->error = error;
		req->info.core_error = 1;
		ocf_core_stats_core_error_update(req->core, OCF_WRITE);
	}

	if (env_atomic_dec_return(&req->req_remaining))
		return;

	OCF_DEBUG_RQ(req, "Completion");

	if (req->error) {
		ocf_req_unlock_wr(req);

		req->complete(req, req->error);

		ocf_req_put(req);
	} else {
		ocf_engine_push_req_front_if(req, &_io_if_wi_flush_metadata,
				true);
	}
}

static int _ocf_write_wi_do(struct ocf_request *req)
{
	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	env_atomic_set(&req->req_remaining, 1); /* One core IO */

	OCF_DEBUG_RQ(req, "Submit");

	/* Submit write IO to the core */
	ocf_submit_volume_req(&req->core->volume, req,
			   _ocf_write_wi_core_complete);

	/* Update statistics */
	ocf_engine_update_block_stats(req);
	ocf_core_stats_request_pt_update(req->core, req->part_id, req->rw,
			req->info.hit_no, req->core_line_count);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}

static void _ocf_write_wi_on_resume(struct ocf_request *req)
{
	OCF_DEBUG_RQ(req, "On resume");
	ocf_engine_push_req_front(req, true);
}

static const struct ocf_io_if _io_if_wi_resume = {
	.read = _ocf_write_wi_do,
	.write = _ocf_write_wi_do,
};

int ocf_write_wi(struct ocf_request *req)
{
	int lock = OCF_LOCK_NOT_ACQUIRED;

	OCF_DEBUG_TRACE(req->cache);

	ocf_io_start(&req->ioi.io);

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	/* Set resume io_if */
	req->io_if = &_io_if_wi_resume;

	ocf_req_hash(req);
	ocf_req_hash_lock_rd(req); /*- Metadata READ access, No eviction --------*/

	/* Travers to check if request is mapped fully */
	ocf_engine_traverse(req);

	if (ocf_engine_mapped_count(req)) {
		/* Some cache line are mapped, lock request for WRITE access */
		lock = ocf_req_async_lock_wr(req, _ocf_write_wi_on_resume);
	} else {
		lock = OCF_LOCK_ACQUIRED;
	}

	ocf_req_hash_unlock_rd(req); /*- END Metadata READ access----------------*/

	if (lock >= 0) {
		if (lock == OCF_LOCK_ACQUIRED) {
			_ocf_write_wi_do(req);
		} else {
			/* WR lock was not acquired, need to wait for resume */
			OCF_DEBUG_RQ(req, "NO LOCK");
		}
	} else {
		OCF_DEBUG_RQ(req, "LOCK ERROR %d", lock);
		req->complete(req, lock);
		ocf_req_put(req);
	}

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}
