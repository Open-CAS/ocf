/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#ifndef __EVICTION_LRU_STRUCTS_H__

#define __EVICTION_LRU_STRUCTS_H__

struct lru_eviction_policy_meta {
	/* LRU pointers 2*4=8 bytes */
	uint32_t prev;
	uint32_t next;
} __attribute__((packed));

struct ocf_lru_list {
	uint32_t num_nodes;
	uint32_t head;
	uint32_t tail;
};

struct lru_eviction_policy {
	struct ocf_lru_list clean;
	struct ocf_lru_list dirty;
};

#endif
