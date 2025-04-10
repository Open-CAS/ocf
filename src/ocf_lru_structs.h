/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __EVICTION_LRU_STRUCTS_H__

#define __EVICTION_LRU_STRUCTS_H__

/* For 4 kB cache lines: 29 bits are enough for up to 2TB cache devices */
#define CACHE_LINE_BITS	29

/* For 4 kB core lines: 34 bits are enough for up to 64TB core devices */
#define CORE_LINE_BITS	34

/* Support 4095 core volumes */
#define CORE_ID_BITS	12
#if OCF_CONFIG_MAX_CORES >= (1 << CORE_ID_BITS)
#error "OCF_CONFIG_MAX_CORES must be less than 1 << CORE_ID_BITS"
#endif

#if CACHE_LINE_BITS + OCF_IO_CLASSES_BITS > 32
#error "'partition_id' can't be a bitfiled within struct ocf_lru_meta anymore"
#endif

struct ocf_lru_meta {
	uint32_t	prev			:CACHE_LINE_BITS,
			partition_id		:OCF_IO_CLASSES_BITS;
	uint32_t	next			:CACHE_LINE_BITS,
			hot			:1,
			unused			:2;
} __attribute__((packed));

struct ocf_lru_list {
	uint32_t num_nodes;
	uint32_t head;
	uint32_t tail;
	uint32_t num_hot;
	uint32_t last_hot;
	bool track_hot;
};

struct ocf_lru_part_meta {
	struct ocf_lru_list clean;
	struct ocf_lru_list dirty;
};

#define OCF_LRU_HOT_RATIO 2

#endif
