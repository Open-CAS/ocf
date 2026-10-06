/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_CLEANING_POLICY_H__
#define __METADATA_CLEANING_POLICY_H__

#include "ocf/ocf.h"

/* Cleaning policy configuration (stored in superblock) */

#define CLEANING_POLICY_CONFIG_BYTES 256
#define CLEANING_POLICY_TYPE_MAX 4

struct cleaning_policy_config {
	uint8_t data[CLEANING_POLICY_CONFIG_BYTES];
} __attribute__((aligned(4)));

struct alru_cleaning_policy_config {
	uint32_t thread_wakeup_time;		/* in seconds */
	uint32_t stale_buffer_time;			/* in seconds */
	uint32_t flush_max_buffers;			/* in lines */
	uint32_t activity_threshold;		/* in milliseconds */
	uint32_t dirty_ratio_threshold;		/* percent */
	uint32_t dirty_ratio_inertia;		/* bytes */
};

struct acp_cleaning_policy_config {
	uint32_t thread_wakeup_time;	/* in milliseconds*/
	uint32_t flush_max_buffers;	/* in lines */
};

/* Cleaning policy metadata per partition */

struct nop_cleaning_policy {
};

struct alru_cleaning_policy {
	env_atomic size;
	uint32_t lru_head;
	uint32_t lru_tail;
};

struct acp_cleaning_policy {
};

struct cleaning_policy {
	union {
		struct nop_cleaning_policy nop;
		struct alru_cleaning_policy alru;
		struct acp_cleaning_policy acp;
	} policy;
};

/* Cleaning policy metadata per cache line */

struct nop_cleaning_policy_meta {
} __attribute__((packed));

struct alru_cleaning_policy_meta {
	/* Lru pointers 2*4=8 bytes */
	uint32_t timestamp;
	uint32_t lru_prev;
	uint32_t lru_next;
} __attribute__((packed));

/* TODO: remove acp metadata */
struct acp_cleaning_policy_meta {
	uint8_t dirty : 1;
};

struct cleaning_policy_meta {
	union {
		struct nop_cleaning_policy_meta nop;
		struct alru_cleaning_policy_meta alru;
		struct acp_cleaning_policy_meta acp;
	} meta;
};

struct cleaning_policy_meta *
ocf_metadata_get_cleaning_policy(struct ocf_cache *cache,
		ocf_cache_line_t line);


#endif /* __METADATA_CLEANING_POLICY_H__ */
