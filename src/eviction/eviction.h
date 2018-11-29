/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#ifndef __LAYER_EVICTION_POLICY_H__

#define __LAYER_EVICTION_POLICY_H__

#define OCF_PENDING_EVICTION_LIMIT 512UL

#include "ocf/ocf.h"
#include "lru.h"
#include "lru_structs.h"

struct eviction_policy {
	union {
		struct lru_eviction_policy lru;
	} policy;
};

/* Eviction policy metadata per cache line */
union eviction_policy_meta {
	struct lru_eviction_policy_meta lru;
} __attribute__((packed));

/* the caller must hold the metadata lock for all operations
 *
 * For range operations the caller can:
 * set core_id to -1 to purge the whole cache device
 * set core_id to -2 to purge the whole cache partition
 */
struct eviction_policy_ops {
	void (*init_cline)(struct ocf_cache *cache,
			ocf_cache_line_t cline);
	void (*rm_cline)(struct ocf_cache *cache,
			ocf_cache_line_t cline);
	bool (*can_evict)(struct ocf_cache *cache);
	uint32_t (*req_clines)(struct ocf_cache *cache,
			uint32_t io_queue, ocf_part_id_t part_id,
			uint32_t cline_no, ocf_core_id_t core_id);
	void (*hot_cline)(struct ocf_cache *cache,
			ocf_cache_line_t cline);
	void (*init_evp)(struct ocf_cache *cache,
			ocf_part_id_t part_id);
	void (*dirty_cline)(struct ocf_cache *cache,
			ocf_part_id_t part_id,
			uint32_t cline_no);
	void (*clean_cline)(struct ocf_cache *cache,
			ocf_part_id_t part_id,
			uint32_t cline_no);
	const char *name;
};

extern struct eviction_policy_ops evict_policy_ops[ocf_eviction_max];

#endif
