/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2022-2023 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_LRU_H__
#define __METADATA_LRU_H__

#include "ocf/ocf.h"

#define OCF_NUM_LRU_LISTS 32

struct ocf_lru_meta {
	uint64_t prev : OCF_CACHE_LINE_BITS;
	uint64_t unused : 3;
	uint64_t next : OCF_CACHE_LINE_BITS;
	uint64_t hot : 1;
	uint64_t unused2 : 2;
	ocf_part_id_t partition_id : 8;
} __attribute__((packed));

struct ocf_lru_list {
	uint32_t num_nodes;
	uint32_t head : OCF_CACHE_LINE_BITS;
	uint32_t tail : OCF_CACHE_LINE_BITS;
	uint32_t num_hot;
	uint32_t last_hot : OCF_CACHE_LINE_BITS;
	bool track_hot;
};

struct ocf_lru_part_meta {
	struct ocf_lru_list clean;
	struct ocf_lru_list dirty;
};

struct ocf_lru_meta *
ocf_metadata_get_lru(
		struct ocf_cache *cache, ocf_cache_line_t line);

#endif /* __METADATA_LRU_H__ */
