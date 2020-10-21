/*
 * Copyright(c) 2012-2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "../ocf_request.h"
#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../eviction/ops.h"
#include "utils_part.h"

static struct ocf_lst_entry *ocf_part_lst_getter_valid(
		struct ocf_cache *cache, ocf_cache_line_t idx)
{
	ENV_BUG_ON(idx > OCF_IO_CLASS_MAX);
	return &cache->user_parts[idx].lst_valid;
}


static int ocf_part_lst_cmp_valid(struct ocf_cache *cache,
		struct ocf_lst_entry *e1, struct ocf_lst_entry *e2)
{
	struct ocf_user_part *p1 = container_of(e1, struct ocf_user_part,
			lst_valid);
	struct ocf_user_part *p2 = container_of(e2, struct ocf_user_part,
			lst_valid);
	size_t p1_size = ocf_cache_is_device_attached(cache) ?
				p1->runtime->curr_size : 0;
	size_t p2_size = ocf_cache_is_device_attached(cache) ?
				p2->runtime->curr_size : 0;

	int v1 = p1->config->priority;
	int v2 = p2->config->priority;

	/*
	 * If partition is invalid the priority depends on current size:
	 * 1. Partition is empty - move to the end of list
	 * 2. Partition is not empty  - move to the beginning of the list. This
	 * partition will be evicted first
	 */

	if (p1->config->priority == OCF_IO_CLASS_PRIO_PINNED)
		p1->config->flags.eviction = false;
	else
		p1->config->flags.eviction = true;

	if (p2->config->priority == OCF_IO_CLASS_PRIO_PINNED)
		p2->config->flags.eviction = false;
	else
		p2->config->flags.eviction = true;

	if (!p1->config->flags.valid) {
		if (p1_size) {
			v1 = SHRT_MAX;
			p1->config->flags.eviction = true;
		} else {
			v1 = SHRT_MIN;
			p1->config->flags.eviction = false;
		}
	}

	if (!p2->config->flags.valid) {
		if (p2_size) {
			v2 = SHRT_MAX;
			p2->config->flags.eviction = true;
		} else {
			v2 = SHRT_MIN;
			p2->config->flags.eviction = false;
		}
	}

	if (v1 == v2) {
		v1 = p1 - cache->user_parts;
		v2 = p2 - cache->user_parts;
	}

	return v2 - v1;
}

void ocf_part_init(struct ocf_cache *cache)
{
	ocf_lst_init(cache, &cache->lst_part, OCF_IO_CLASS_MAX,
			ocf_part_lst_getter_valid, ocf_part_lst_cmp_valid);
}

void ocf_part_move(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;
	struct ocf_map_info *entry;
	ocf_cache_line_t line;
	ocf_part_id_t id_old, id_new;
	uint32_t i;
	ocf_cleaning_t type = cache->conf_meta->cleaning_policy_type;

	ENV_BUG_ON(type >= ocf_cleaning_max);

	entry = &req->map[0];
	for (i = 0; i < req->core_line_count; i++, entry++) {
		if (!entry->re_part) {
			/* Changing partition not required */
			continue;
		}

		if (entry->status != LOOKUP_HIT) {
			/* No HIT */
			continue;
		}

		line = entry->coll_idx;
		id_old = ocf_metadata_get_partition_id(cache, line);
		id_new = req->part_id;

		ENV_BUG_ON(id_old >= OCF_IO_CLASS_MAX ||
				id_new >= OCF_IO_CLASS_MAX);

		if (id_old == id_new) {
			/* Partition of the request and cache line is the same,
			 * no need to change partition
			 */
			continue;
		}

		/* Remove from old eviction */
		ocf_eviction_purge_cache_line(cache, line);

		if (metadata_test_dirty(cache, line)) {
			/*
			 * Remove cline from cleaning - this if for ioclass
			 * oriented cleaning policy (e.g. ALRU).
			 * TODO: Consider adding update_cache_line() ops
			 * to cleaning policy to let policies handle this.
			 */
			if (cleaning_policy_ops[type].purge_cache_block)
				cleaning_policy_ops[type].
						purge_cache_block(cache, line);
		}

		/* Let's change partition */
		ocf_metadata_remove_from_partition(cache, id_old, line);
		ocf_metadata_add_to_partition(cache, id_new, line);

		/* Add to new eviction */
		ocf_eviction_init_cache_line(cache, line);
		ocf_eviction_set_hot_cache_line(cache, line);

		/* Check if cache line is dirty. If yes then need to change
		 * cleaning  policy and update partition dirty clines
		 * statistics.
		 */
		if (metadata_test_dirty(cache, line)) {
			/* Add cline back to cleaning policy */
			if (cleaning_policy_ops[type].set_hot_cache_line)
				cleaning_policy_ops[type].
					set_hot_cache_line(cache, line);

			env_atomic_inc(&req->core->runtime_meta->
					part_counters[id_new].dirty_clines);
			env_atomic_dec(&req->core->runtime_meta->
					part_counters[id_old].dirty_clines);
		}

		env_atomic_inc(&req->core->runtime_meta->
				part_counters[id_new].cached_clines);
		env_atomic_dec(&req->core->runtime_meta->
				part_counters[id_old].cached_clines);

		/* DONE */
	}
}

void ocf_part_set_valid(struct ocf_cache *cache, ocf_part_id_t id,
		bool valid)
{
	struct ocf_user_part *part = &cache->user_parts[id];

	if (valid ^ part->config->flags.valid) {
		if (valid) {
			part->config->flags.valid = true;
			cache->conf_meta->valid_parts_no++;
		} else {
			part->config->flags.valid = false;
			cache->conf_meta->valid_parts_no--;
			part->config->priority = OCF_IO_CLASS_PRIO_LOWEST;
			part->config->min_size = 0;
			part->config->max_size = PARTITION_SIZE_MAX;
			ENV_BUG_ON(env_strncpy(part->config->name, sizeof(part->config->name),
					"Inactive", 9));
		}
	}
}

static inline uint32_t ocf_part_evict_size(struct ocf_request *req)
{
	uint32_t needed_cache_lines, part_available, cache_lines_to_evict;
	uint32_t part_occupancy, part_occupancy_debt;
	struct ocf_user_part *target_part = &req->cache->user_parts[req->part_id];
	uint32_t part_occupancy_limit =
		ocf_part_get_max_size(req->cache, target_part);

	needed_cache_lines = ocf_engine_repart_count(req) +
		ocf_engine_unmapped_count(req);

	part_occupancy = ocf_part_get_occupancy(target_part);

	if (part_occupancy_limit >= part_occupancy) {
		part_available = part_occupancy_limit - part_occupancy;
		part_occupancy_debt = 0;
	} else {
		/* Occupancy is greater than occupancy limit. Evict missing number of
		 * cachelines, but no more than single eviction limit */
		part_occupancy_debt = min((uint32_t)OCF_PENDING_EVICTION_LIMIT,
				part_occupancy - part_occupancy_limit);
		part_available = 0;
	}

	if (ocf_freelist_num_free(req->cache->freelist) <
			ocf_engine_unmapped_count(req)) {
		/* Number of cachelines to insert greater than number of free
		 * cachelines */
		if (part_available >= needed_cache_lines) {
			/* Cache is full, but target's part occupancy limit is not reached
			   */
			ocf_req_clear_part_evict(req);
			cache_lines_to_evict = needed_cache_lines;
		} else {
			/* Cache is full and target part reached it's occupancy limit */
			ocf_req_set_part_evict(req);
			cache_lines_to_evict = needed_cache_lines - part_available;
		}

	} else if (part_available < needed_cache_lines) {
		/* Enough of free cache lines, but partition reached it's occupancy
		 * limit */
		cache_lines_to_evict = needed_cache_lines - part_available;
		ocf_req_set_part_evict(req);

	} else if (part_available >= needed_cache_lines) {
		/* Enough free cachelines available and they can be assigned to target
		 * partition */
		cache_lines_to_evict = 0;

	}

	return cache_lines_to_evict + part_occupancy_debt;
}

uint32_t ocf_part_check_space(struct ocf_request *req, uint32_t *to_evict)
{
	uint32_t ret = OCF_PART_IS_FULL;
	uint32_t _to_evict;
	struct ocf_user_part *target_part = &req->cache->user_parts[req->part_id];

	if (!ocf_part_is_enabled(target_part) &&
			ocf_part_get_occupancy(target_part) == 0) {
		/* If partition is disabled, but has assigned cachelines, eviction has
		 *  to be triggered */
		return OCF_PART_IS_DISABLED;
	}

	_to_evict = ocf_part_evict_size(req);

	if (_to_evict == 0)
		ret = OCF_PART_HAS_SPACE;

	if (to_evict)
		*to_evict = _to_evict;

	return ret;
}
