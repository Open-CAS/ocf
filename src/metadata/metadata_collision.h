/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2025 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_COLLISION_H__
#define __METADATA_COLLISION_H__

/**
 * @brief Metadata map structure
 */

struct ocf_metadata_list_info {
	ocf_cache_line_t prev_col;
		/*!<  Previous cache line in collision list */
	ocf_cache_line_t next_col;
		/*!<  Next cache line in collision list*/
} __attribute__((packed));

/**
 * @brief Metadata map structure
 */

struct ocf_metadata_map {
	uint64_t core_line;
		/*!<  Core line addres on cache mapped by this strcture */

	uint16_t core_id;
		/*!<  ID of core where is assigned this cache line*/

	uint8_t status[];
		/*!<  Entry status structure e.g. valid, dirty...*/
} __attribute__((packed));

void ocf_metadata_set_collision_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next, ocf_cache_line_t prev);

void ocf_metadata_set_collision_next(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next);

void ocf_metadata_set_collision_prev(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t prev);

void ocf_metadata_get_collision_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t *next, ocf_cache_line_t *prev);

static inline ocf_cache_line_t ocf_metadata_get_collision_next(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	ocf_cache_line_t next;

	ocf_metadata_get_collision_info(cache, line, &next, NULL);
	return next;
}

static inline ocf_cache_line_t ocf_metadata_get_collision_prev(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	ocf_cache_line_t prev;

	ocf_metadata_get_collision_info(cache, line, NULL, &prev);
	return prev;
}

void ocf_metadata_add_to_collision(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t core_line,
		ocf_cache_line_t hash, ocf_cache_line_t cache_line);

void ocf_metadata_remove_from_collision(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t part_id);

void ocf_metadata_start_collision_shared_access(
		struct ocf_cache *cache, ocf_cache_line_t line);

void ocf_metadata_end_collision_shared_access(
		struct ocf_cache *cache, ocf_cache_line_t line);

#endif /* METADATA_COLLISION_H_ */
