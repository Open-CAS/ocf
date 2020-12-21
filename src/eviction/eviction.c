/*
 * Copyright(c) 2012-2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "eviction.h"
#include "ops.h"
#include "../utils/utils_part.h"
#include "../engine/engine_common.h"

struct eviction_policy_ops evict_policy_ops[ocf_eviction_max] = {
	[ocf_eviction_lru] = {
		.init_cline = evp_lru_init_cline,
		.rm_cline = evp_lru_rm_cline,
		.req_clines = evp_lru_req_clines,
		.hot_cline = evp_lru_hot_cline,
		.init_evp = evp_lru_init_evp,
		.dirty_cline = evp_lru_dirty_cline,
		.clean_cline = evp_lru_clean_cline,
		.flush_dirty = evp_lru_clean,
		.name = "lru",
	},
};

static uint32_t ocf_evict_calculate(ocf_cache_t cache,
		struct ocf_user_part *part, uint32_t to_evict)
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

	if (to_evict > (curr_part_size - min_part_size))
		to_evict = curr_part_size - min_part_size;

	return to_evict;
}

static inline uint32_t ocf_evict_part_do(struct ocf_request *req,
		struct ocf_user_part *target_part)
{
	uint32_t unmapped = ocf_engine_unmapped_count(req);
	uint32_t to_evict = 0;

	if (!evp_lru_can_evict(req->cache))
		return 0;

	to_evict = ocf_evict_calculate(req->cache, target_part, unmapped);

	if (to_evict < unmapped) {
		/* cannot evict enough cachelines to map request,
		   so no purpose in evicting anything */
		return 0;
	}

	return ocf_eviction_need_space(req->cache, req, target_part, to_evict);
}

static inline uint32_t ocf_evict_do(struct ocf_request *req)
{
	uint32_t to_evict = 0, evicted = 0;
	struct ocf_user_part *part;
	ocf_part_id_t target_part_id = req->part_id;
	ocf_cache_t cache = req->cache;
	uint32_t evict_cline_no = ocf_engine_unmapped_count(req);
	struct ocf_user_part *target_part = &cache->user_parts[target_part_id];
	ocf_part_id_t part_id;
	bool oversized = true;

repeat:
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

		/* in first loop iteration only consider overflown partitions */
		if (oversized && ocf_part_overflow_size(cache, part) == 0)
			continue;

		to_evict = ocf_evict_calculate(cache, part, evict_cline_no -
				evicted);
		if (to_evict == 0) {
			/* No cache lines to evict for this partition */
			continue;
		}

		evicted += ocf_eviction_need_space(cache, req, part, to_evict);

		if (evicted >= evict_cline_no) {
			/* Evicted requested number of cache line, stop */
			goto out;
		}

	}

	if (oversized) {
		oversized = false;
		goto repeat;
	}

out:
	return evicted;
}

int space_managment_evict_do(struct ocf_request *req)
{
	uint32_t needed = ocf_engine_unmapped_count(req);
	uint32_t evicted;
	struct ocf_user_part *req_part = &req->cache->user_parts[req->part_id];

	if (ocf_req_part_evict(req)) {
		evicted = ocf_evict_part_do(req, req_part);
	} else {
		evicted = ocf_evict_do(req);
	}

	if (needed <= evicted)
		return LOOKUP_INSERTED;

	ocf_req_set_mapping_error(req);
	return LOOKUP_MISS;
}
