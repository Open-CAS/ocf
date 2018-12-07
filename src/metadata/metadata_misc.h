/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_MISC_H__
#define __METADATA_MISC_H__

/*
 * Hash function needs number that has no common factors with both number
 * of cores and number of entries in metadata hash container (hash lists).
 * This can be easily achived by picking prime which is bigger than maximum
 * number of cores and ensuring that count of hash table entries is not
 * divisible by this number. Let's choose 4099, which is smallest prime
 * greater than OCF_CORE_MAX (which is 4096).
 */
#define OCF_HASH_PRIME 4099

static inline ocf_cache_line_t ocf_metadata_hash_func(ocf_cache_t cache,
		uint64_t core_line_num, ocf_core_id_t core_id)
{
	return (ocf_cache_line_t) ((core_line_num * OCF_HASH_PRIME + core_id) %
			cache->device->hash_table_entries);
}

void ocf_metadata_sparse_cache_line(struct ocf_cache *cache,
		ocf_cache_line_t cache_line);

int ocf_metadata_sparse_range(struct ocf_cache *cache, int core_id,
			uint64_t start_byte, uint64_t end_byte);

typedef void (*ocf_metadata_actor_t)(struct ocf_cache *cache,
		ocf_cache_line_t cache_line);

int ocf_metadata_actor(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_core_id_t core_id,
		uint64_t start_byte, uint64_t end_byte,
		ocf_metadata_actor_t actor);

#endif /* __METADATA_MISC_H__ */
