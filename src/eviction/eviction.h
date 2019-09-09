/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __LAYER_EVICTION_POLICY_H__
#define __LAYER_EVICTION_POLICY_H__

#include "ocf/ocf.h"
#include "lru.h"
#include "lru_structs.h"
#include "../ocf_request.h"

#define OCF_TO_EVICTION_MIN 128UL
#define OCF_PENDING_EVICTION_LIMIT 512UL

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
	void (*init_cline)(ocf_cache_t cache, ocf_cache_line_t cline);
	void (*rm_cline)(ocf_cache_t cache,
			ocf_cache_line_t cline);
	bool (*can_evict)(ocf_cache_t cache);
	uint32_t (*req_clines)(ocf_cache_t cache,
			ocf_queue_t io_queue, ocf_part_id_t part_id,
			uint32_t cline_no);
	void (*hot_cline)(ocf_cache_t cache,
			ocf_cache_line_t cline);
	void (*init_evp)(ocf_cache_t cache,
			ocf_part_id_t part_id);
	void (*dirty_cline)(ocf_cache_t cache,
			ocf_part_id_t part_id,
			uint32_t cline_no);
	void (*clean_cline)(ocf_cache_t cache,
			ocf_part_id_t part_id,
			uint32_t cline_no);
	const char *name;
};

extern struct eviction_policy_ops evict_policy_ops[ocf_eviction_max];

/*
 * Deallocates space from low priority partitions.
 *
 * Returns -1 on error
 * or the destination partition ID for the free buffers
 * (it matches label and is part of the object (#core_id) IO group)
 */
int space_managment_evict_do(ocf_cache_t cache,
		struct ocf_request *req, uint32_t evict_cline_no);

int space_management_free(ocf_cache_t cache, uint32_t count);

#endif
