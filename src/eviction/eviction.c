/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "eviction.h"
#include "ops.h"
#include "../utils/utils_part.h"

struct eviction_policy_ops evict_policy_ops[ocf_eviction_max] = {
	[ocf_eviction_lru] = {
		.init_cline = evp_lru_init_cline,
		.rm_cline = evp_lru_rm_cline,
		.req_clines = evp_lru_req_clines,
		.hot_cline = evp_lru_hot_cline,
		.init_evp = evp_lru_init_evp,
		.dirty_cline = evp_lru_dirty_cline,
		.clean_cline = evp_lru_clean_cline,
		.name = "lru",
	},
};

static uint32_t ocf_evict_calculate(ocf_cache_t cache,
		struct ocf_user_part *part, uint32_t to_evict, bool roundup)
{

	uint32_t curr_part_size = ocf_part_get_occupancy(part);
	uint32_t min_part_size = ocf_part_get_min_size(cache, part);

	if (curr_part_size <= min_part_size) {
		/*
		 * Cannot evict from this partition because current size
		 * is less than minimum size
		 */
		return 0;
	}

	if (roundup && to_evict < OCF_TO_EVICTION_MIN)
		to_evict = OCF_TO_EVICTION_MIN;

	if (to_evict > (curr_part_size - min_part_size))
		to_evict = curr_part_size - min_part_size;

	return to_evict;
}

static inline uint32_t ocf_evict_part_do(ocf_cache_t cache,
		ocf_queue_t io_queue, const uint32_t evict_cline_no,
		struct ocf_user_part *target_part)
{
	uint32_t to_evict = 0;

	if (!evp_lru_can_evict(cache))
		return 0;

	to_evict = ocf_evict_calculate(cache, target_part, evict_cline_no,
			false);

	return ocf_eviction_need_space(cache, io_queue,
			target_part, to_evict);
}

static inline uint32_t ocf_evict_partitions(ocf_cache_t cache,
		ocf_queue_t io_queue, uint32_t evict_cline_no,
		bool overflown_only, int16_t max_priority)
{
	uint32_t to_evict = 0, evicted = 0;
	struct ocf_user_part *part;
	ocf_part_id_t part_id;
	unsigned overflow_size;

	/* For each partition from the lowest priority to highest one */
	for_each_part(cache, part, part_id) {
		if (!ocf_eviction_can_evict(cache))
			goto out;

		/*
		 * Check stop and continue conditions
		 */
		if (max_priority > part->config->priority) {
			/*
			 * iterate partition have higher priority,
			 * do not evict
			 */
			break;
		}
		if (!overflown_only && !part->config->flags.eviction) {
			/* If partition is overflown it should be evcited
			 * even if its pinned
			 */
			break;
		}

		if (overflown_only) {
			overflow_size = ocf_part_overflow_size(cache, part);
			if (overflow_size == 0)
				continue;
		}

		to_evict = ocf_evict_calculate(cache, part,
				evict_cline_no - evicted, true);
		if (to_evict == 0) {
			/* No cache lines to evict for this partition */
			continue;
		}

		if (overflown_only)
			to_evict = OCF_MIN(to_evict, overflow_size);

		evicted += ocf_eviction_need_space(cache, io_queue,
				part, to_evict);

		if (evicted >= evict_cline_no) {
			/* Evicted requested number of cache line, stop
			 */
			goto out;
		}

	}

out:
	return evicted;
}

static inline uint32_t ocf_evict_do(ocf_cache_t cache,
		ocf_queue_t io_queue, uint32_t evict_cline_no,
		struct ocf_user_part *target_part)
{
	uint32_t evicted;

	/* First attempt to evict overflown partitions in order to
	 * achieve configured maximum size. Ignoring partitions
	 * priority in this case, as overflown partitions should
	 * free its cachelines regardless of destination partition
	 * priority. */

	evicted = ocf_evict_partitions(cache, io_queue, evict_cline_no,
		true, OCF_IO_CLASS_PRIO_PINNED);
	if (evicted >= evict_cline_no)
		return evicted;
	/* Not enough cachelines in overflown partitions. Go through
	 * partitions with priority <= target partition and attempt
	 * to evict from those. */
	evict_cline_no -= evicted;
	evicted += ocf_evict_partitions(cache, io_queue, evict_cline_no,
		false, target_part->config->priority);

	return evicted;
}

int space_managment_evict_do(struct ocf_cache *cache,
		struct ocf_request *req, uint32_t evict_cline_no)
{
	uint32_t evicted;
	uint32_t free;
	struct ocf_user_part *req_part = &cache->user_parts[req->part_id];

	if (ocf_req_part_evict(req)) {
		evicted = ocf_evict_part_do(cache, req->io_queue, evict_cline_no,
				req_part);
	} else {
		free = ocf_freelist_num_free(cache->freelist);
		if (evict_cline_no <= free)
			return LOOKUP_INSERTED;

		evict_cline_no -= free;

		evicted = ocf_evict_do(cache, req->io_queue, evict_cline_no, req_part);
	}

	if (evict_cline_no <= evicted)
		return LOOKUP_INSERTED;

	ocf_req_set_mapping_error(req);
	return LOOKUP_MISS;
}
