/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_CORE_H__
#define __METADATA_CORE_H__

static inline void ocf_metadata_set_core_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_core_id_t core_id,
		uint64_t core_sector)
{
	cache->metadata.iface.set_core_info(cache, line, core_id,
			core_sector);
}

static inline void ocf_metadata_get_core_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_core_id_t *core_id,
		uint64_t *core_sector)
{
	cache->metadata.iface.get_core_info(cache, line, core_id,
			core_sector);
}

static inline void ocf_metadata_get_core_and_part_id(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_core_id_t *core_id, ocf_part_id_t *part_id)
{
	cache->metadata.iface.get_core_and_part_id(cache, line, core_id,
			part_id);
}

static inline ocf_core_id_t ocf_metadata_get_core_id(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	return cache->metadata.iface.get_core_id(cache, line);
}

static inline struct ocf_metadata_uuid *ocf_metadata_get_core_uuid(
		struct ocf_cache *cache, ocf_core_id_t core_id)
{
	return cache->metadata.iface.get_core_uuid(cache, core_id);
}

#endif /* METADATA_CORE_H_ */
