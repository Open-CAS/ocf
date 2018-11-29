/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#ifndef __LAYER_CLEANING_POLICY_AGGRESSIVE_H__

#define __LAYER_CLEANING_POLICY_AGGRESSIVE_H__

#include "cleaning.h"

void cleaning_policy_acp_setup(struct ocf_cache *cache);

int cleaning_policy_acp_initialize(struct ocf_cache *cache,
		int init_metadata);

void cleaning_policy_acp_deinitialize(struct ocf_cache *cache);

int cleaning_policy_acp_perform_cleaning(struct ocf_cache *cache,
		uint32_t io_queue);

void cleaning_policy_acp_init_cache_block(struct ocf_cache *cache,
		uint32_t cache_line);

void cleaning_policy_acp_set_hot_cache_line(struct ocf_cache *cache,
		uint32_t cache_line);

void cleaning_policy_acp_purge_block(struct ocf_cache *cache,
		uint32_t cache_line);

int cleaning_policy_acp_purge_range(struct ocf_cache *cache,
		int core_id, uint64_t start_byte, uint64_t end_byte);

int cleaning_policy_acp_set_cleaning_param(struct ocf_cache *cache,
		uint32_t param_id, uint32_t param_value);

int cleaning_policy_acp_get_cleaning_param(struct ocf_cache *cache,
		uint32_t param_id, uint32_t *param_value);

int cleaning_policy_acp_add_core(ocf_cache_t cache, ocf_core_id_t core_id);

void cleaning_policy_acp_remove_core(ocf_cache_t cache,
		ocf_core_id_t core_id);

#endif

