/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "metadata.h"
#include "../utils/utils_cache_line.h"

/*
 *
 */
void ocf_metadata_add_to_collision(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t core_line,
		ocf_cache_line_t hash, ocf_cache_line_t cache_line)
{
	ocf_cache_line_t prev_cache_line = ocf_metadata_get_hash(cache, hash);
	ocf_cache_line_t line_entries = cache->device->collision_table_entries;
	ocf_cache_line_t hash_entries = cache->device->hash_table_entries;

	ENV_BUG_ON(!(hash < hash_entries));
	ENV_BUG_ON(!(cache_line < line_entries));

	/* Setup new node */
	ocf_metadata_set_core_info(cache, cache_line, core_id,
			core_line);

	/* Update collision info:
	 * - next is set to value from hash table;
	 * - previous is set to collision table entries value
	 */
	ocf_metadata_set_collision_info(cache, cache_line, prev_cache_line,
			line_entries);

	/* Update previous head */
	if (prev_cache_line != line_entries) {
		ocf_metadata_set_collision_prev(cache, prev_cache_line,
				cache_line);
	}

	/* Update hash Table: hash table contains pointer to
	 * collision table so it contains indexes in collision table
	 */
	ocf_metadata_set_hash(cache, hash, cache_line);
}

/*
 *
 */
void ocf_metadata_remove_from_collision(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t part_id)
{
	ocf_core_id_t core_id;
	uint64_t core_sector;
	ocf_cache_line_t hash_father;
	ocf_cache_line_t prev_line, next_line;
	ocf_cache_line_t line_entries = cache->device->collision_table_entries;
	ocf_cache_line_t hash_entries = cache->device->hash_table_entries;

	ENV_BUG_ON(!(line < line_entries));

	ocf_metadata_get_collision_info(cache, line, &next_line, &prev_line);

	/* Update previous node if any. */
	if (prev_line != line_entries)
		ocf_metadata_set_collision_next(cache, prev_line, next_line);

	/* Update next node if any. */
	if (next_line != line_entries)
		ocf_metadata_set_collision_prev(cache, next_line, prev_line);

	ocf_metadata_get_core_info(cache, line, &core_id, &core_sector);

	/* Update hash table, because if it was pointing to the given node it
	 * must now point to the given's node next
	 */
	hash_father = ocf_metadata_hash_func(cache, core_sector, core_id);
	ENV_BUG_ON(!(hash_father < hash_entries));

	if (ocf_metadata_get_hash(cache, hash_father) == line)
		ocf_metadata_set_hash(cache, hash_father, next_line);

	ocf_metadata_set_collision_info(cache, line,
			line_entries, line_entries);

	ocf_metadata_set_core_info(cache, line,
			OCF_CORE_MAX, ULLONG_MAX);
}
