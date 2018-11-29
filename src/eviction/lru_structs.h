/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#ifndef __EVICTION_LRU_STRUCTS_H__

#define __EVICTION_LRU_STRUCTS_H__

struct lru_eviction_policy_meta {
	/* LRU pointers 2*4=8 bytes */
	uint32_t prev;
	uint32_t next;
} __attribute__((packed));

struct lru_eviction_policy {
	int has_clean_nodes;
	int has_dirty_nodes;
	uint32_t dirty_head;
	uint32_t dirty_tail;
	uint32_t clean_head;
	uint32_t clean_tail;
};

#endif
