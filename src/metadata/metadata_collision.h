/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_COLLISION_H__
#define __METADATA_COLLISION_H__

/**
 * @brief Metadata map structure
 */

/* Keep the struct ocf_metadata_list_info size of 8 bytes */
#define STRUCT_MD_LIST_INFO_SIZE	8

struct ocf_metadata_list_info {
	union {
		struct {
			ocf_cache_line_t	prev_col	:CACHE_LINE_BITS,
			/*!<  Previous cache line in collision list */
						pf_alg_id	:OCF_PA_ID_MAX_BITS;
			/*!<  prefetch algorithm-id */
			ocf_cache_line_t	next_col	:CACHE_LINE_BITS,
			/*!<  Next cache line in collision list*/
						unused		:3;
		} __attribute__((packed));
		uint64_t entry;
	};
} __attribute__((packed));

struct ocf_hash_entry {
	union {
		struct {
			uint32_t line:CACHE_LINE_BITS;
			/* Hash lock bits */
			uint32_t rd:2;
			uint32_t wr:1;
		};
		uint32_t raw;
	};
};

/**
 * @brief Metadata map structure
 */

struct ocf_metadata_map {
	/* Core line is aligned to PAGE_SIZE in the worst case, so we don't keep
	 * the least significant bits (12) that are all zeros.
	 * Largest supported volume is 64 TB. */
	uint64_t core_line : CORE_LINE_BITS;
		/*!<  Core line addres on cache mapped by this strcture */
	uint64_t core_id : CORE_ID_BITS;
		/*!<  ID of core where is assigned this cache line*/
	uint16_t _valid : 1;
		/*!<  valid bit for 4K cache line */
	uint16_t _dirty : 1;
		/*!<  dirty bit for 4K cache line */
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
