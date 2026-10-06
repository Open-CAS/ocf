/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_MISC_H__
#define __METADATA_MISC_H__

#include "metadata_collision.h"

/* See ocf_metadata_collision_hash() */
static inline ocf_cache_line_t ocf_metadata_hash_func(ocf_cache_t cache,
		uint64_t core_line_num, ocf_core_id_t core_id)
{
	return ocf_metadata_collision_hash(cache->device->hash_table_entries,
			core_line_num, core_id);
}

/* Return the hash based on the hash of the prev core line */
static inline ocf_cache_line_t ocf_metadata_hash_next(ocf_cache_t cache,
		ocf_cache_line_t hash)
{
	return ocf_metadata_collision_hash_next(
			cache->device->hash_table_entries, hash);
}

void ocf_metadata_remove_cache_line(struct ocf_cache *cache,
		ocf_cache_line_t cache_line);

void ocf_metadata_sparse_cache_line(struct ocf_cache *cache,
		ocf_cache_line_t cache_line);

int ocf_metadata_sparse_range(struct ocf_cache *cache, int core_id,
			uint64_t start_byte, uint64_t end_byte);

int ocf_metadata_detach_cline_range(ocf_cache_t cache, ocf_cache_line_t begin,
		ocf_cache_line_t end);

int ocf_metadata_restore_cline_range(ocf_cache_t cache, ocf_cache_line_t begin,
		ocf_cache_line_t end);

#endif /* __METADATA_MISC_H__ */
