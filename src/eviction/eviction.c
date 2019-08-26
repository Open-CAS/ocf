/*
 * Copyright(c) 2012-2018 Intel Corporation
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

static uint32_t ocf_evict_calculate(struct ocf_user_part *part,
		uint32_t to_evict)
{
	if (part->runtime->curr_size <= part->config->min_size) {
		/*
		 * Cannot evict from this partition because current size
		 * is less than minimum size
		 */
		return 0;
	}

	if (to_evict < OCF_TO_EVICTION_MIN)
		to_evict = OCF_TO_EVICTION_MIN;

	if (to_evict > (part->runtime->curr_size - part->config->min_size))
		to_evict = part->runtime->curr_size - part->config->min_size;

	return to_evict;
}

static inline uint32_t ocf_evict_do(ocf_cache_t cache,
		ocf_queue_t io_queue, const uint32_t evict_cline_no,
		ocf_part_id_t target_part_id)
{
	uint32_t to_evict = 0, evicted = 0;
	struct ocf_user_part *part;
	struct ocf_user_part *target_part = &cache->user_parts[target_part_id];
	ocf_part_id_t part_id;

	/* For each partition from the lowest priority to highest one */
	for_each_part(cache, part, part_id) {

		if (!ocf_eviction_can_evict(cache))
			goto out;

		/*
		 * Check stop and continue conditions
		 */
		if (target_part->config->priority > part->config->priority) {
			/*
			 * iterate partition have higher priority, do not evict
			 */
			break;
		}
		if (!part->config->flags.eviction) {
			/* It seams that no more partition for eviction */
			break;
		}
		if (part_id == target_part_id) {
			/* Omit targeted, evict from different first */
			continue;
		}
		if (evicted >= evict_cline_no) {
			/* Evicted requested number of cache line, stop */
			goto out;
		}

		to_evict = ocf_evict_calculate(part, evict_cline_no);
		if (to_evict == 0) {
			/* No cache lines to evict for this partition */
			continue;
		}

		evicted += ocf_eviction_need_space(cache, io_queue,
				part_id, to_evict);
	}

	if (!ocf_eviction_can_evict(cache))
		goto out;

	if (evicted < evict_cline_no) {
		/* Now we can evict form targeted partition */
		to_evict = ocf_evict_calculate(target_part, evict_cline_no);
		if (to_evict) {
			evicted += ocf_eviction_need_space(cache, io_queue,
					target_part_id, to_evict);
		}
	}

out:
	return evicted;
}

int space_managment_evict_do(struct ocf_cache *cache,
		struct ocf_request *req, uint32_t evict_cline_no)
{
	uint32_t evicted;
	uint32_t free;

	free = ocf_freelist_num_free(cache->freelist);
	if (evict_cline_no <= free)
		return LOOKUP_MAPPED;

	evict_cline_no -= free;
	evicted = ocf_evict_do(cache, req->io_queue, evict_cline_no,
			req->part_id);

	if (evict_cline_no <= evicted)
		return LOOKUP_MAPPED;

	req->info.mapping_error |= true;
	return LOOKUP_MISS;
}
