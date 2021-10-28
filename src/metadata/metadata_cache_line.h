/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_CACHE_LINE_H__
#define __METADATA_CACHE_LINE_H__

static inline ocf_cache_line_size_t ocf_line_size(struct ocf_cache *cache)
{
	return cache->metadata.line_size;
}

static inline uint64_t ocf_line_sectors(struct ocf_cache *cache)
{
	return BYTES_TO_SECTORS(cache->metadata.line_size);
}

static inline uint64_t ocf_line_end_sector(struct ocf_cache *cache)
{
	return ocf_line_sectors(cache) - 1;
}

#endif /* __METADATA_CACHE_LINE_H__ */
