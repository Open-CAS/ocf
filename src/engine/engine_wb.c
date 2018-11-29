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
#include "../utils/utils_rq.h"
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

static void _ocf_write_wb_update_bits(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	if (ocf_engine_is_miss(rq)) {
		OCF_METADATA_LOCK_RD();
		/* Update valid status bits */
		ocf_set_valid_map_info(rq);

		OCF_METADATA_UNLOCK_RD();
	}

	if (!ocf_engine_is_dirty_all(rq)) {
		OCF_METADATA_LOCK_WR();

		/* set dirty bits, and mark if metadata flushing is required */
		ocf_set_dirty_map_info(rq);

		OCF_METADATA_UNLOCK_WR();
	}
}

static void _ocf_write_wb_io_flush_metadata(void *private_data, int error)
{
	struct ocf_request *rq = (struct ocf_request *) private_data;

	if (error)
		rq->error = error;

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	if (rq->error)
		ocf_engine_error(rq, true, "Failed to write data to cache");

	ocf_rq_unlock_wr(rq);

	rq->complete(rq, rq->error);

	ocf_rq_put(rq);
}

static int ocf_write_wb_do_flush_metadata(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	env_atomic_set(&rq->req_remaining, 1); /* One core IO */

	if (rq->info.flush_metadata) {
		OCF_DEBUG_RQ(rq, "Flush metadata");
		ocf_metadata_flush_do_asynch(cache, rq,
				_ocf_write_wb_io_flush_metadata);
	}

	_ocf_write_wb_io_flush_metadata(rq, 0);

	return 0;
}

static const struct ocf_io_if _io_if_wb_flush_metadata = {
		.read = ocf_write_wb_do_flush_metadata,
		.write = ocf_write_wb_do_flush_metadata,
};

static void _ocf_write_wb_io(void *private_data, int error)
{
	struct ocf_request *rq = (struct ocf_request *) private_data;

	if (error) {
		env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				cache_errors.write);
		rq->error |= error;
	}

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	OCF_DEBUG_RQ(rq, "Completion");

	if (rq->error) {
		ocf_engine_error(rq, true, "Failed to write data to cache");

		ocf_rq_unlock_wr(rq);

		rq->complete(rq, rq->error);

		ocf_rq_put(rq);
	} else {
		ocf_engine_push_rq_front_if(rq, &_io_if_wb_flush_metadata,
				true);
	}
}


static inline void _ocf_write_wb_submit(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	env_atomic_set(&rq->req_remaining, ocf_engine_io_count(rq));

	/*
	 * 1. Submit data
	 * 2. Wait for completion of data
	 * 3. Then continue processing request (flush metadata)
	 */

	if (rq->info.re_part) {
		OCF_DEBUG_RQ(rq, "Re-Part");

		OCF_METADATA_LOCK_WR();

		/* Probably some cache lines are assigned into wrong
		 * partition. Need to move it to new one
		 */
		ocf_part_move(rq);

		OCF_METADATA_UNLOCK_WR();
	}

	OCF_DEBUG_RQ(rq, "Submit Data");

	/* Data IO */
	ocf_submit_cache_reqs(cache, rq->map, rq, OCF_WRITE,
			ocf_engine_io_count(rq), _ocf_write_wb_io, rq);
}

int ocf_write_wb_do(struct ocf_request *rq)
{
	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* Updata status bits */
	_ocf_write_wb_update_bits(rq);

	/* Submit IO */
	_ocf_write_wb_submit(rq);

	/* Updata statistics */
	ocf_engine_update_request_stats(rq);
	ocf_engine_update_block_stats(rq);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}

int ocf_write_wb(struct ocf_request *rq)
{
	bool mapped;
	int lock = OCF_LOCK_NOT_ACQUIRED;
	struct ocf_cache *cache = rq->cache;

	ocf_io_start(rq->io);

	/* Not sure if we need this. */
	ocf_rq_get(rq);

	/* Set resume call backs */
	rq->resume = ocf_engine_on_resume;
	rq->io_if = &_io_if_wb_resume;

	/* TODO: Handle fits into dirty */

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
				ocf_write_wb_do(rq);
			}
		} else {
			OCF_DEBUG_RQ(rq, "LOCK ERROR %d", lock);
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
