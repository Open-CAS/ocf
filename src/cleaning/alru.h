/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#ifndef __LAYER_CLEANING_POLICY_ALRU_H__

#define __LAYER_CLEANING_POLICY_ALRU_H__

#include "cleaning.h"
#include "alru_structs.h"

void cleaning_policy_alru_setup(struct ocf_cache *cache);
int cleaning_policy_alru_initialize(struct ocf_cache *cache,
		int init_metadata);
void cleaning_policy_alru_init_cache_block(struct ocf_cache *cache,
		uint32_t cache_line);
void cleaning_policy_alru_purge_cache_block(struct ocf_cache *cache,
		uint32_t cache_line);
int cleaning_policy_alru_purge_range(struct ocf_cache *cache, int core_id,
		uint64_t start_byte, uint64_t end_byte);
void cleaning_policy_alru_set_hot_cache_line(struct ocf_cache *cache,
		uint32_t cache_line);
int cleaning_policy_alru_set_cleaning_param(struct ocf_cache *cache,
		uint32_t param_id, uint32_t param_value);
int cleaning_policy_alru_get_cleaning_param(struct ocf_cache *cache,
		uint32_t param_id, uint32_t *param_value);
int cleaning_alru_perform_cleaning(struct ocf_cache *cache, uint32_t io_queue);

#endif

