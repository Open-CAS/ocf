/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2022-2023 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_LAYOUT_COLLISION_H__
#define __METADATA_LAYOUT_COLLISION_H__

#include "../../ocf_def_priv.h"

/**
 * @brief Metadata map structure
 */

struct ocf_metadata_list_info {
	union {
		struct {
			/* Previous cache line in collision list */
			ocf_cache_line_t prev_col : OCF_CACHE_LINE_BITS;
			ocf_cache_line_t unused : 3;
			/* Next cache line in collision list*/
			ocf_cache_line_t next_col : OCF_CACHE_LINE_BITS;
			ocf_cache_line_t unused2 : 3;
		} __attribute__((packed));
		uint64_t entry;
	};
};

/* Keep the struct ocf_metadata_list_info size of 8 bytes */
_Static_assert(sizeof(struct ocf_metadata_list_info) == sizeof(uint64_t),
	       "Size of struct ocf_metadata_list_info is not equal to 8 bytes");

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
 * @brief Hash bucket of core line
 *
 * Hash function intentionally returns consecutive (modulo @hash_entries)
 * values for consecutive @core_line. This way it is trivial to sort all
 * core lines within a single request in ascending hash value order. This kind
 * of sorting is required to assure that (future) hash bucket metadata locks are
 * always acquired in fixed order, eliminating the risk of dead locks.
 *
 * @param hash_entries - Number of entries in hash segment
 * @param core_line - Core line number
 * @param core_id - Core id
 */
static inline ocf_cache_line_t ocf_metadata_collision_hash(
		ocf_cache_line_t hash_entries, uint64_t core_line,
		ocf_core_id_t core_id)
{
	return (ocf_cache_line_t) ((core_line + (core_id * (hash_entries / 32)))
			% hash_entries);
}

/**
 * @brief Hash bucket following given one
 *
 * @param hash_entries - Number of entries in hash segment
 * @param hash - Hash bucket
 */
static inline ocf_cache_line_t ocf_metadata_collision_hash_next(
		ocf_cache_line_t hash_entries, ocf_cache_line_t hash)
{
	hash++;
	return likely(hash < hash_entries) ? hash : 0;
}

/**
 * @brief Metadata map structure
 */

struct ocf_metadata_map {
	uint64_t core_line : OCF_CORE_LINE_BITS;
		/*!<  Core line address on cache mapped by this structure */

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

#endif /* __METADATA_LAYOUT_COLLISION_H__ */
