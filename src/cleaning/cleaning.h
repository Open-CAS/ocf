/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __LAYER_CLEANING_POLICY_H__
#define __LAYER_CLEANING_POLICY_H__

#include "alru_structs.h"
#include "nop_structs.h"
#include "acp_structs.h"

#define CLEANING_POLICY_CONFIG_BYTES 256
#define CLEANING_POLICY_TYPE_MAX 4

struct ocf_request;

struct cleaning_policy_config {
	uint8_t data[CLEANING_POLICY_CONFIG_BYTES];
	struct acp_cleaning_policy_config acp;
};

struct cleaning_policy {
	union {
		struct nop_cleaning_policy nop;
		struct alru_cleaning_policy alru;
	} policy;
};

/* Cleaning policy metadata per cache line */
struct cleaning_policy_meta {
	union {
		struct nop_cleaning_policy_meta nop;
		struct alru_cleaning_policy_meta alru;
		struct acp_cleaning_policy_meta acp;
	} meta;
};

struct cleaning_policy_ops {
	void (*setup)(struct ocf_cache *cache);
	int (*initialize)(struct ocf_cache *cache, int init_metadata);
	void (*deinitialize)(struct ocf_cache *cache);
	int (*add_core)(struct ocf_cache *cache, ocf_core_id_t core_id);
	void (*remove_core)(struct ocf_cache *cache, ocf_core_id_t core_id);
	void (*init_cache_block)(struct ocf_cache *cache, uint32_t cache_line);
	void (*purge_cache_block)(struct ocf_cache *cache,
			uint32_t cache_line);
	int (*purge_range)(struct ocf_cache *cache, int core_id,
			uint64_t start_byte, uint64_t end_byte);
	void (*set_hot_cache_line)(struct ocf_cache *cache,
			uint32_t cache_line);
	int (*set_cleaning_param)(struct ocf_cache *cache,
			uint32_t param_id, uint32_t param_value);
	int (*get_cleaning_param)(struct ocf_cache *cache,
			uint32_t param_id, uint32_t *param_value);
	/**
	 * @brief Performs cleaning.
	 * @return requested time (in ms) of next call
	 */
	int (*perform_cleaning)(struct ocf_cache *cache,
			uint32_t io_queue);
	const char *name;
};

extern struct cleaning_policy_ops cleaning_policy_ops[ocf_cleaning_max];

struct ocf_cleaner {
	void *priv;
};

int ocf_start_cleaner(struct ocf_cache *cache);

void ocf_stop_cleaner(struct ocf_cache *cache);

#endif
