/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "cache_engine.h"
#include "engine_common.h"
#include "engine_wb.h"
#include "../metadata/metadata.h"
#include "../ocf_request.h"
#include "../utils/utils_io.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_part.h"
#include "../concurrency/ocf_concurrency.h"

#define OCF_ENGINE_DEBUG_IO_NAME "wb"
#include "engine_debug.h"

static const struct ocf_io_if _io_if_wb_resume = {
	.read = ocf_write_wb_do,
	.write = ocf_write_wb_do,
};

static void _ocf_write_wb_update_bits(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	if (ocf_engine_is_miss(req)) {
		OCF_METADATA_LOCK_RD();
		/* Update valid status bits */
		ocf_set_valid_map_info(req);

		OCF_METADATA_UNLOCK_RD();
	}

	if (!ocf_engine_is_dirty_all(req)) {
		OCF_METADATA_LOCK_WR();

		/* set dirty bits, and mark if metadata flushing is required */
		ocf_set_dirty_map_info(req);

		OCF_METADATA_UNLOCK_WR();
	}
}

static void _ocf_write_wb_io_flush_metadata(struct ocf_request *req, int error)
{
	if (error)
		req->error = error;

	if (env_atomic_dec_return(&req->req_remaining))
		return;

	if (req->error)
		ocf_engine_error(req, true, "Failed to write data to cache");

	ocf_req_unlock_wr(req);

	req->complete(req, req->error);

	ocf_req_put(req);
}

static int ocf_write_wb_do_flush_metadata(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	env_atomic_set(&req->req_remaining, 1); /* One core IO */

	if (req->info.flush_metadata) {
		OCF_DEBUG_RQ(req, "Flush metadata");
		ocf_metadata_flush_do_asynch(cache, req,
				_ocf_write_wb_io_flush_metadata);
	}

	_ocf_write_wb_io_flush_metadata(req, 0);

	return 0;
}

static const struct ocf_io_if _io_if_wb_flush_metadata = {
		.read = ocf_write_wb_do_flush_metadata,
		.write = ocf_write_wb_do_flush_metadata,
};

static void _ocf_write_wb_complete(struct ocf_request *req, int error)
{
	if (error) {
		ocf_core_stats_cache_error_update(req->core, OCF_WRITE);
		req->error |= error;
	}

	if (env_atomic_dec_return(&req->req_remaining))
		return;

	OCF_DEBUG_RQ(req, "Completion");

	if (req->error) {
		ocf_engine_error(req, true, "Failed to write data to cache");

		ocf_req_unlock_wr(req);

		req->complete(req, req->error);

		ocf_req_put(req);
	} else {
		ocf_engine_push_req_front_if(req, &_io_if_wb_flush_metadata,
				true);
	}
}


static inline void _ocf_write_wb_submit(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	env_atomic_set(&req->req_remaining, ocf_engine_io_count(req));

	/*
	 * 1. Submit data
	 * 2. Wait for completion of data
	 * 3. Then continue processing request (flush metadata)
	 */

	if (req->info.re_part) {
		OCF_DEBUG_RQ(req, "Re-Part");

		OCF_METADATA_LOCK_WR();

		/* Probably some cache lines are assigned into wrong
		 * partition. Need to move it to new one
		 */
		ocf_part_move(req);

		OCF_METADATA_UNLOCK_WR();
	}

	OCF_DEBUG_RQ(req, "Submit Data");

	/* Data IO */
	ocf_submit_cache_reqs(cache, req, OCF_WRITE, 0, req->byte_length,
			ocf_engine_io_count(req), _ocf_write_wb_complete);
}

int ocf_write_wb_do(struct ocf_request *req)
{
	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	/* Update status bits */
	_ocf_write_wb_update_bits(req);

	/* Submit IO */
	_ocf_write_wb_submit(req);

	/* Update statistics */
	ocf_engine_update_request_stats(req);
	ocf_engine_update_block_stats(req);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}

int ocf_write_wb(struct ocf_request *req)
{
	bool mapped;
	int lock = OCF_LOCK_NOT_ACQUIRED;
	struct ocf_cache *cache = req->cache;

	ocf_io_start(&req->ioi.io);

	/* Not sure if we need this. */
	ocf_req_get(req);

	/* Set resume io_if */
	req->io_if = &_io_if_wb_resume;

	/* TODO: Handle fits into dirty */

	OCF_METADATA_LOCK_RD(); /*- Metadata READ access, No eviction --------*/

	/* Travers to check if request is mapped fully */
	ocf_engine_traverse(req);

	mapped = ocf_engine_is_mapped(req);
	if (mapped) {
		/* All cache line are mapped, lock request for WRITE access */
		lock = ocf_req_async_lock_wr(req, ocf_engine_on_resume);
	}

	OCF_METADATA_UNLOCK_RD(); /*- END Metadata READ access----------------*/

	if (!mapped) {
		OCF_METADATA_LOCK_WR(); /*- Metadata WR access, eviction -----*/

		/* Now there is exclusive access for metadata. May traverse once
		 * again. If there are misses need to call eviction. This
		 * process is called 'mapping'.
		 */
		ocf_engine_map(req);

		if (!req->info.mapping_error) {
			/* Lock request for WRITE access */
			lock = ocf_req_async_lock_wr(req, ocf_engine_on_resume);
		}

		OCF_METADATA_UNLOCK_WR(); /*- END Metadata WR access ---------*/
	}

	if (!req->info.mapping_error) {
		if (lock >= 0) {
			if (lock != OCF_LOCK_ACQUIRED) {
				/* WR lock was not acquired, need to wait for resume */
				OCF_DEBUG_RQ(req, "NO LOCK");
			} else {
				ocf_write_wb_do(req);
			}
		} else {
			OCF_DEBUG_RQ(req, "LOCK ERROR %d", lock);
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
