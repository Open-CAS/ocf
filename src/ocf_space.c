/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf_space.h"
#include "utils/utils_user_part.h"
#include "engine/engine_common.h"
#include "prefetch/ocf_evict_counters.h"

#define	EVICT_RETRY			2
#define MORE_THAN_60_PCT(_a, _b)	((uint64_t)(_a) * 5 > (uint64_t)(_b) * 3)

static uint32_t ocf_evict_calculate(ocf_cache_t cache,
		struct ocf_user_part *user_part, uint32_t to_evict)
{
	struct ocf_lru_part_meta *lru = user_part->part.runtime->lru;
	uint dirty = 0;
	uint i;
	uint32_t curr_part_size = ocf_part_get_occupancy(&user_part->part);
	uint32_t min_part_size = ocf_user_part_get_min_size(cache, user_part);

	if (curr_part_size <= min_part_size) {
		/*
		 * Cannot evict from this partition because current size
		 * is less than minimum size
		 */
		return 0;
	}
	/*
	 * OCF: If cache is more than 60% dirty then
	 *	return 0 to force dirty lines eviction
	 */
	for (i = 0; i < OCF_NUM_LRU_LISTS; i++) {
		dirty += lru[i].dirty.num_nodes;
	}
	if (MORE_THAN_60_PCT(dirty, cache->device->collision_table_entries)) {
		return 0;
	}

	if (to_evict > (curr_part_size - min_part_size))
		to_evict = curr_part_size - min_part_size;

	return to_evict;
}

static inline uint32_t ocf_evict_part_do(struct ocf_request *req,
		struct ocf_user_part *user_part)
{
	uint32_t unmapped = ocf_engine_unmapped_count(req);
	uint32_t to_evict = 0;

	to_evict = ocf_evict_calculate(req->cache, user_part, unmapped);

	if (to_evict < unmapped) {
		/* cannot evict enough cachelines to map request,
		   so no purpose in evicting anything */
		return 0;
	}

	return ocf_lru_req_clines(req, &user_part->part, to_evict);
}

static inline uint32_t ocf_evict_user_partitions(ocf_cache_t cache,
		struct ocf_request *req, uint32_t evict_cline_no,
		bool overflown_only, int16_t max_priority)
{
	uint32_t to_evict = 0, evicted = 0, evicted_now;
	struct ocf_user_part *user_part;
	ocf_part_id_t part_id;
	unsigned overflow_size;
	int i;
	int32_t counter = 0;
	bool no_more_counters = true;

	/* prepare to try evict twice in case all counters are 0 */
	for (i = 0; i < EVICT_RETRY; i++) {
	/* For each partition from the lowest priority to highest one */
	for_each_user_part(cache, user_part, part_id) {
		/*
		 * Check stop and continue conditions
		 */
		if (max_priority > user_part->config->priority) {
			/*
			 * iterate partition have higher priority,
			 * do not evict
			 */
			break;
		}
		if (!overflown_only && !user_part->config->flags.eviction) {
			/* If partition is overflown it should be evcited
			 * even if its pinned
			 */
			break;
		}

		if (overflown_only) {
			overflow_size = ocf_user_part_overflow_size(cache, user_part);
			if (overflow_size == 0)
				continue;
		}

		to_evict = ocf_evict_calculate(cache, user_part,
				evict_cline_no - evicted);
		if (to_evict == 0) {
			/* No cache lines to evict for this partition */
			continue;
		}

		if (overflown_only)
			to_evict = OCF_MIN(to_evict, overflow_size);

		if (!overflown_only) {
			counter = ocf_evict_counters_inc(cache, part_id,
				-(int32_t)to_evict);
			if (counter <= -(int32_t)to_evict) {
				ocf_evict_counters_inc(cache, part_id,
					to_evict);
				counter += to_evict;
				goto after_evict;
			}
		}
		evicted += evicted_now =
			ocf_lru_req_clines(req, &user_part->part, to_evict);
		if (!overflown_only && evicted_now < to_evict) {
			ocf_evict_counters_inc(cache, part_id,
				to_evict - evicted_now);
			counter += to_evict - evicted_now;
		}
after_evict:
		if (counter > 0)
			no_more_counters = false;
		if (evicted >= evict_cline_no) {
			/* Evicted requested number of cache line, stop
			 */
			goto out;
		}

	}
	if (overflown_only)
		break;
	else if (no_more_counters)
		/* update evict counters and try again */
		ocf_evict_counters_update(cache, max_priority);
	}

out:
	return evicted;
}

static inline uint32_t ocf_remap_do(struct ocf_request *req)
{
	ocf_cache_t cache = req->cache;
	ocf_part_id_t target_part_id = req->part_id;
	struct ocf_user_part *target_part = &cache->user_parts[target_part_id];
	uint32_t remap_cline_no = ocf_engine_unmapped_count(req);
	uint32_t remapped = 0;

	/* First attempt to map from freelist */
	if (ocf_lru_num_free(cache) > 0)
		remapped = ocf_lru_req_clines(req, &cache->free, remap_cline_no);

	if (remapped >= remap_cline_no)
		return remapped;

	/* Attempt to evict overflown partitions in order to
	 * achieve configured maximum size. Ignoring partitions
	 * priority in this case, as overflown partitions should
	 * free its cachelines regardless of destination partition
	 * priority. */
	remapped += ocf_evict_user_partitions(cache, req, remap_cline_no - remapped,
		true, OCF_IO_CLASS_PRIO_PINNED);
	if (remapped >= remap_cline_no)
		return remapped;

	/* Not enough cachelines in overflown partitions. Go through
	 * partitions with priority <= target partition and attempt
	 * to evict from those. */
	remap_cline_no -= remapped;
	remapped += ocf_evict_user_partitions(cache, req, remap_cline_no,
		false, target_part->config->priority);

	return remapped;
}

int ocf_space_managment_remap_do(struct ocf_request *req)
{
	uint32_t needed = ocf_engine_unmapped_count(req);
	uint32_t remapped;
	struct ocf_user_part *req_part = &req->cache->user_parts[req->part_id];

	if (ocf_req_part_evict(req)) {
		remapped = ocf_evict_part_do(req, req_part);
	} else {
		remapped = ocf_remap_do(req);
	}

	if (needed <= remapped)
		return LOOKUP_REMAPPED;

	return LOOKUP_MISS;
}
