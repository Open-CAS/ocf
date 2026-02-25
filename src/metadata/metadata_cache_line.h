/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_CACHE_LINE_H__
#define __METADATA_CACHE_LINE_H__

static inline ocf_cache_line_size_t ocf_line_size(struct ocf_cache *cache)
{
	return cache->metadata.line_size;
}

static inline ocf_cache_line_t ocf_line_count(struct ocf_cache *cache)
{
	return cache->conf_meta->cachelines;
}

static inline uint64_t ocf_line_blocks(struct ocf_cache *cache)
{
	return BYTES_TO_BLOCKS_ROUND_DOWN(cache->metadata.line_size);
}

static inline uint64_t ocf_line_end_block(struct ocf_cache *cache)
{
	return ocf_line_blocks(cache) - 1;
}

#endif /* __METADATA_CACHE_LINE_H__ */
