/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2022-2023 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_COLLISION_H__
#define __METADATA_COLLISION_H__

#include "../ocf_def_priv.h"

/**
 * @brief Metadata map structure
 */

struct ocf_metadata_list_info {
	/* Previous cache line in collision list */
	ocf_cache_line_t prev_col : OCF_CACHE_LINE_BITS;
	ocf_cache_line_t unused : 3;
	/* Next cache line in collision list*/
	ocf_cache_line_t next_col : OCF_CACHE_LINE_BITS;
	ocf_cache_line_t unused2 : 3;
} __attribute__((packed));

/* Keep the struct ocf_metadata_list_info size of 8 bytes */
_Static_assert(sizeof(struct ocf_metadata_list_info) == sizeof(uint64_t));

struct ocf_hash_entry {
	union {
		struct {
			uint32_t line : OCF_CACHE_LINE_BITS;
			/* Hash lock bits */
			uint32_t rd : 2;
			uint32_t wr : 1;
		};
		uint32_t raw;
	};
};

/**
 * @brief Metadata map structure
 */

struct ocf_metadata_map {
	uint64_t core_line : OCF_CORE_LINE_BITS;
		/*!<  Core line addres on cache mapped by this strcture */

	uint64_t core_id : OCF_CORE_ID_BITS;
		/*!<  ID of core where is assigned this cache line*/

#ifdef OCF_BLOCK_SIZE_4K
	uint64_t _valid : 1;
		/*!<  valid bit for 4K cache line */

	uint64_t _dirty : 1;
		/*!<  dirty bit for 4K cache line */
#endif

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
