/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "utils_cache_line.h"

static inline void ocf_cleaning_set_hot_cache_line(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	ocf_cleaning_t cleaning_type = cache->conf_meta->cleaning_policy_type;

	ENV_BUG_ON(cleaning_type >= ocf_cleaning_max);

	if (cleaning_policy_ops[cleaning_type].set_hot_cache_line) {
		cleaning_policy_ops[cleaning_type].
				set_hot_cache_line(cache, line);
	}
}

static void __set_cache_line_invalid(struct ocf_cache *cache, uint8_t start_bit,
		uint8_t end_bit, ocf_cache_line_t line,
		ocf_core_id_t core_id, ocf_part_id_t part_id)
{
	bool is_valid;

	ENV_BUG_ON(core_id >= OCF_CORE_MAX);

	if (metadata_clear_valid_sec_changed(cache, line, start_bit, end_bit,
			&is_valid)) {
		/*
		 * Update the number of cached data for that core object
		 */
		env_atomic_dec(&cache->core_runtime_meta[core_id].
				cached_clines);
		env_atomic_dec(&cache->core_runtime_meta[core_id].
				part_counters[part_id].cached_clines);
	}

	/* If we have waiters, do not remove cache line
	 * for this cache line which will use one, clear
	 * only valid bits
	 */
	if (!is_valid && !ocf_cache_line_are_waiters(cache, line)) {
		ocf_purge_eviction_policy(cache, line);
		ocf_metadata_sparse_cache_line(cache, line);
	}
}

void set_cache_line_invalid(struct ocf_cache *cache, uint8_t start_bit,
		uint8_t end_bit, struct ocf_request *req, uint32_t map_idx)
{
	ocf_cache_line_t line = req->map[map_idx].coll_idx;
	ocf_part_id_t part_id;
	ocf_core_id_t core_id;

	ENV_BUG_ON(!req);

	part_id = ocf_metadata_get_partition_id(cache, line);
	core_id = req->core_id;

	__set_cache_line_invalid(cache, start_bit, end_bit, line, core_id,
			part_id);

	ocf_metadata_flush_mark(cache, req, map_idx, INVALID, start_bit,
			end_bit);
}

void set_cache_line_invalid_no_flush(struct ocf_cache *cache, uint8_t start_bit,
		uint8_t end_bit, ocf_cache_line_t line)
{
	ocf_part_id_t part_id;
	ocf_core_id_t core_id;

	ocf_metadata_get_core_and_part_id(cache, line, &core_id, &part_id);

	__set_cache_line_invalid(cache, start_bit, end_bit, line, core_id,
			part_id);
}

void set_cache_line_valid(struct ocf_cache *cache, uint8_t start_bit,
		uint8_t end_bit, struct ocf_request *req, uint32_t map_idx)
{
	ocf_core_id_t core_id = req->core_id;
	ocf_cache_line_t line = req->map[map_idx].coll_idx;
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache, line);

	ENV_BUG_ON(!(core_id < OCF_CORE_MAX));

	if (metadata_set_valid_sec_changed(cache, line, start_bit, end_bit)) {
		/*
		 * Update the number of cached data for that core object
		 */
		env_atomic_inc(&cache->core_runtime_meta[core_id].
				cached_clines);
		env_atomic_inc(&cache->core_runtime_meta[core_id].
				part_counters[part_id].cached_clines);
	}
}

void set_cache_line_clean(struct ocf_cache *cache, uint8_t start_bit,
		uint8_t end_bit, struct ocf_request *req, uint32_t map_idx)
{
	ocf_core_id_t core_id = req->core_id;
	ocf_cache_line_t line = req->map[map_idx].coll_idx;
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache, line);
	uint8_t evp_type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(!(core_id < OCF_CORE_MAX));

	if (metadata_clear_dirty_sec_changed(cache, line, start_bit, end_bit)) {
		/*
		 * Update the number of dirty cached data for that
		 * core object
		 */
		if (env_atomic_dec_and_test(&cache->core_runtime_meta[core_id].
				dirty_clines)) {
			/*
			 * If this is last dirty cline reset dirty
			 * timestamp
			 */
			env_atomic64_set(&cache->core_runtime_meta[core_id].
					dirty_since, 0);
		}

		/*
		 * decrement dirty clines statistic for given cline
		 */
		env_atomic_dec(&cache->core_runtime_meta[core_id].
				part_counters[part_id].dirty_clines);

		if (likely(evict_policy_ops[evp_type].clean_cline))
			evict_policy_ops[evp_type].clean_cline(cache, part_id, line);

		ocf_purge_cleaning_policy(cache, line);
		ocf_metadata_flush_mark(cache, req, map_idx, CLEAN, start_bit, end_bit);
	}
}

void set_cache_line_dirty(struct ocf_cache *cache, uint8_t start_bit,
		uint8_t end_bit, struct ocf_request *req, uint32_t map_idx)
{
	ocf_core_id_t core_id = req->core_id;
	ocf_cache_line_t line = req->map[map_idx].coll_idx;
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache, line);
	uint8_t evp_type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(!(core_id < OCF_CORE_MAX));

	if (metadata_set_dirty_sec_changed(cache, line, start_bit, end_bit)) {
		/*
		 * If this is first dirty cline set dirty timestamp
		 */
		env_atomic64_cmpxchg(&cache->core_runtime_meta[core_id].
				dirty_since, 0,	env_get_tick_count());

		/*
		 * Update the number of dirty cached data for that
		 * core object
		 */
		env_atomic_inc(&cache->core_runtime_meta[core_id].dirty_clines);

		/*
		 * increment dirty clines statistic for given cline
		 */
		env_atomic_inc(&cache->core_runtime_meta[core_id].
				part_counters[part_id].dirty_clines);

		if (likely(evict_policy_ops[evp_type].dirty_cline))
			evict_policy_ops[evp_type].dirty_cline(cache, part_id, line);
	
		ocf_metadata_flush_mark(cache, req, map_idx, DIRTY, start_bit, end_bit);
	}

	ocf_cleaning_set_hot_cache_line(cache, line);
}
