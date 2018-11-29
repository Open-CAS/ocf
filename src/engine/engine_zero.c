/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_zero.h"
#include "engine_common.h"
#include "../concurrency/ocf_concurrency.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_io.h"
#include "../metadata/metadata.h"

#define OCF_ENGINE_DEBUG_IO_NAME "zero"
#include "engine_debug.h"

static int ocf_zero_purge(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	if (rq->error) {
		ocf_engine_error(rq, true, "Failed to discard data on cache");
	} else {
		/* There are mapped cache line, need to remove them */

		OCF_METADATA_LOCK_WR(); /*- Metadata WR access ---------------*/

		/* Remove mapped cache lines from metadata */
		ocf_purge_map_info(rq);

		OCF_METADATA_UNLOCK_WR(); /*- END Metadata WR access ---------*/
	}

	ocf_rq_unlock_wr(rq);

	rq->complete(rq, rq->error);

	ocf_rq_put(rq);

	return 0;
}

static const struct ocf_io_if _io_if_zero_purge = {
	.read = ocf_zero_purge,
	.write = ocf_zero_purge,
};

static void _ocf_zero_io_flush_metadata(void *private_data, int error)
{
	struct ocf_request *rq = (struct ocf_request *) private_data;

	if (error) {
		env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				cache_errors.write);
		rq->error = error;
	}

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	ocf_engine_push_rq_front_if(rq, &_io_if_zero_purge, true);
}

static inline void ocf_zero_map_info(struct ocf_request *rq)
{
	uint32_t map_idx = 0;
	uint8_t start_bit;
	uint8_t end_bit;
	struct ocf_map_info *map = rq->map;
	struct ocf_cache *cache = rq->cache;
	uint32_t count = rq->core_line_count;

	/* Purge range on the basis of map info
	 *
	 * | 01234567 | 01234567 | ... | 01234567 | 01234567 |
	 * | -----+++ | ++++++++ | +++ | ++++++++ | +++++--- |
	 * |   first  |          Middle           |   last   |
	 */

	for (map_idx = 0; map_idx < count; map_idx++) {
		if (map[map_idx].status == LOOKUP_MISS)
			continue;

		start_bit = 0;
		end_bit = ocf_line_end_sector(cache);

		if (map_idx == 0) {
			/* First */
			start_bit = BYTES_TO_SECTORS(rq->byte_position)
					% ocf_line_sectors(cache);
		}

		if (map_idx == (count - 1)) {
			/* Last */
			end_bit = BYTES_TO_SECTORS(rq->byte_position +
					rq->byte_length - 1) %
					ocf_line_sectors(cache);
		}

		ocf_metadata_flush_mark(cache, rq, map_idx, INVALID,
				start_bit, end_bit);
	}
}

static int _ocf_zero_do(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* Mark cache lines for zeroing/discarding */
	ocf_zero_map_info(rq);

	/* Discard marked cache lines */
	env_atomic_set(&rq->req_remaining, 1);
	if (rq->info.flush_metadata) {
		/* Request was dirty and need to flush metadata */
		ocf_metadata_flush_do_asynch(cache, rq,
		                _ocf_zero_io_flush_metadata);
	}
	_ocf_zero_io_flush_metadata(rq, 0);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}

static const struct ocf_io_if _io_if_ocf_zero_do = {
	.read = _ocf_zero_do,
	.write = _ocf_zero_do,
};

/**
 * @note
 *	- Caller has to have metadata write lock
 *	- Core line has to be mapped
 */
void ocf_engine_zero_line(struct ocf_request *rq)
{
	int lock = OCF_LOCK_NOT_ACQUIRED;

	ENV_BUG_ON(rq->core_line_count != 1);

	/* Traverse to check if request is mapped */
	ocf_engine_traverse(rq);

	ENV_BUG_ON(!ocf_engine_is_mapped(rq));

	rq->resume = ocf_engine_on_resume;
	rq->io_if = &_io_if_ocf_zero_do;

	/* Some cache line are mapped, lock request for WRITE access */
	lock = ocf_rq_trylock_wr(rq);

	if (lock >= 0) {
		ENV_BUG_ON(lock != OCF_LOCK_ACQUIRED);
		ocf_engine_push_rq_front_if(rq, &_io_if_ocf_zero_do, true);
	} else {
		OCF_DEBUG_RQ(rq, "LOCK ERROR %d", lock);
		rq->complete(rq, lock);
		ocf_rq_put(rq);
	}
}

