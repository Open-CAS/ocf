/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "metadata.h"
#include "../ocf_freelist.h"
#include "../utils/utils_cache_line.h"

static bool _is_cache_line_acting(struct ocf_cache *cache,
		uint32_t cache_line, ocf_core_id_t core_id,
		uint64_t start_line, uint64_t end_line)
{
	ocf_core_id_t tmp_core_id;
	uint64_t core_line;

	ocf_metadata_get_core_info(cache, cache_line,
		&tmp_core_id, &core_line);

	if (core_id != OCF_CORE_ID_INVALID) {
		if (core_id != tmp_core_id)
			return false;

		if (core_line < start_line || core_line > end_line)
			return false;

	} else if (tmp_core_id == OCF_CORE_ID_INVALID) {
		return false;
	}

	return true;
}

/*
 * Iterates over cache lines that belong to the core device with
 * core ID = core_id  whose core byte addresses are in the range
 * [start_byte, end_byte] and applies actor(cache, cache_line) to all
 * matching cache lines
 *
 * set partition_id to PARTITION_INVALID to not care about partition_id
 *
 * METADATA lock must be held before calling this function
 */
int ocf_metadata_actor(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_core_id_t core_id,
		uint64_t start_byte, uint64_t end_byte,
		ocf_metadata_actor_t actor)
{
	uint32_t step = 0;
	ocf_cache_line_t i, next_i;
	uint64_t start_line, end_line;
	int ret = 0;

	start_line = ocf_bytes_2_lines(cache, start_byte);
	end_line = ocf_bytes_2_lines(cache, end_byte);

	if (part_id != PARTITION_INVALID) {
		for (i = cache->user_parts[part_id].runtime->head;
				i != cache->device->collision_table_entries;
				i = next_i) {
			next_i = ocf_metadata_get_partition_next(cache, i);

			if (_is_cache_line_acting(cache, i, core_id,
					start_line, end_line)) {
				if (ocf_cache_line_is_used(cache, i))
					ret = -OCF_ERR_AGAIN;
				else
					actor(cache, i);
			}

			OCF_COND_RESCHED_DEFAULT(step);
		}
	} else {
		for (i = 0; i < cache->device->collision_table_entries; ++i) {
			if (_is_cache_line_acting(cache, i, core_id,
					start_line, end_line)) {
				if (ocf_cache_line_is_used(cache, i))
					ret = -OCF_ERR_AGAIN;
				else
					actor(cache, i);
			}

			OCF_COND_RESCHED_DEFAULT(step);
		}
	}

	return ret;
}

/* the caller must hold the relevant cache block concurrency reader lock
 * and the metadata lock
 */
void ocf_metadata_sparse_cache_line(struct ocf_cache *cache,
		uint32_t cache_line)
{
	ocf_part_id_t partition_id =
			ocf_metadata_get_partition_id(cache, cache_line);

	ocf_metadata_remove_from_collision(cache, cache_line, partition_id);

	ocf_metadata_remove_from_partition(cache, partition_id, cache_line);

	ocf_freelist_put_cache_line(cache->freelist, cache_line);
}

static void _ocf_metadata_sparse_cache_line(struct ocf_cache *cache,
		uint32_t cache_line)
{
	ocf_metadata_start_collision_shared_access(cache, cache_line);

	set_cache_line_invalid_no_flush(cache, 0, ocf_line_end_sector(cache),
			cache_line);

	/*
	 * This is especially for removing inactive core
	 */
	metadata_clear_dirty(cache, cache_line);

	ocf_metadata_end_collision_shared_access(cache, cache_line);
}

/* caller must hold metadata lock
 * set core_id to -1 to clean the whole cache device
 */
int ocf_metadata_sparse_range(struct ocf_cache *cache, int core_id,
			  uint64_t start_byte, uint64_t end_byte)
{
	return ocf_metadata_actor(cache, PARTITION_INVALID, core_id,
		start_byte, end_byte, _ocf_metadata_sparse_cache_line);
}
