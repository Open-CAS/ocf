/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __LAYER_CLEANING_POLICY_H__
#define __LAYER_CLEANING_POLICY_H__

#include "alru_structs.h"
#include "nop_structs.h"
#include "acp_structs.h"
#include "ocf/ocf_cleaner.h"

#define CLEANING_POLICY_CONFIG_BYTES 256
#define CLEANING_POLICY_TYPE_MAX 4

#define SLEEP_TIME_MS (1000)

struct ocf_request;

struct cleaning_policy_config {
	uint8_t data[CLEANING_POLICY_CONFIG_BYTES];
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
	void (*setup)(ocf_cache_t cache);
	int (*initialize)(ocf_cache_t cache, int init_metadata);
	void (*deinitialize)(ocf_cache_t cache);
	int (*add_core)(ocf_cache_t cache, ocf_core_id_t core_id);
	void (*remove_core)(ocf_cache_t cache, ocf_core_id_t core_id);
	void (*init_cache_block)(ocf_cache_t cache, uint32_t cache_line);
	void (*purge_cache_block)(ocf_cache_t cache, uint32_t cache_line);
	int (*purge_range)(ocf_cache_t cache, int core_id,
			uint64_t start_byte, uint64_t end_byte);
	void (*set_hot_cache_line)(ocf_cache_t cache, uint32_t cache_line);
	int (*set_cleaning_param)(ocf_cache_t cache, uint32_t param_id,
			uint32_t param_value);
	int (*get_cleaning_param)(ocf_cache_t cache, uint32_t param_id,
			uint32_t *param_value);
	void (*perform_cleaning)(ocf_cache_t cache, ocf_cleaner_end_t cmpl);
	const char *name;
};

extern struct cleaning_policy_ops cleaning_policy_ops[ocf_cleaning_max];

struct ocf_cleaner {
	void *cleaning_policy_context;
	ocf_queue_t io_queue;
	ocf_cleaner_end_t end;
	void *priv;
};

int ocf_start_cleaner(ocf_cache_t cache);

void ocf_kick_cleaner(ocf_cache_t cache);

void ocf_stop_cleaner(ocf_cache_t cache);

#endif
