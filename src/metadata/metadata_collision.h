/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
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
	ocf_cache_line_t partition_prev;
		/*!<  Previous cache line in the same partition*/
	ocf_cache_line_t partition_next;
		/*!<  Next cache line in the same partition*/
	ocf_part_id_t partition_id : 8;
		/*!<  ID of partition where is assigned this cache line*/
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

static inline ocf_cache_line_t ocf_metadata_map_lg2phy(
		struct ocf_cache *cache, ocf_cache_line_t coll_idx)
{
	return cache->metadata.iface.layout_iface->lg2phy(cache,
		    coll_idx);
}

static inline ocf_cache_line_t ocf_metadata_map_phy2lg(
		struct ocf_cache *cache, ocf_cache_line_t cache_line)
{
	return cache->metadata.iface.layout_iface->phy2lg(cache,
		    cache_line);
}

static inline void ocf_metadata_set_collision_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next, ocf_cache_line_t prev)
{
	cache->metadata.iface.set_collision_info(cache, line, next, prev);
}

static inline void ocf_metadata_get_collision_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t *next, ocf_cache_line_t *prev)
{
	cache->metadata.iface.get_collision_info(cache, line, next, prev);
}

static inline void ocf_metadata_set_collision_next(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next)
{
	cache->metadata.iface.set_collision_next(cache, line, next);
}

static inline void ocf_metadata_set_collision_prev(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t prev)
{
	cache->metadata.iface.set_collision_prev(cache, line, prev);
}

static inline ocf_cache_line_t ocf_metadata_get_collision_next(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	return cache->metadata.iface.get_collision_next(cache, line);
}

static inline ocf_cache_line_t ocf_metadata_get_collision_prev(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	return cache->metadata.iface.get_collision_prev(cache, line);
}

void ocf_metadata_add_to_collision(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t core_line,
		ocf_cache_line_t hash, ocf_cache_line_t cache_line);

void ocf_metadata_remove_from_collision(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t part_id);

#endif /* METADATA_COLLISION_H_ */
