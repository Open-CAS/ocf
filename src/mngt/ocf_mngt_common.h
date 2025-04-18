/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2025 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */


#ifndef __OCF_MNGT_COMMON_H__
#define __OCF_MNGT_COMMON_H__

#include "ocf_env_refcnt.h"
#include "../utils/utils_pipeline.h"

void cache_mngt_core_deinit(ocf_core_t core);

void cache_mngt_core_remove_from_meta(ocf_core_t core);

void cache_mngt_core_remove_from_cache(ocf_core_t core);

void cache_mngt_core_deinit_attached_meta(ocf_core_t core);

void cache_mngt_core_remove_from_cleaning_pol(ocf_core_t core);

int _ocf_cleaning_thread(void *priv);

int cache_mngt_thread_io_requests(void *data);

int ocf_mngt_add_partition_to_cache(struct ocf_cache *cache,
		ocf_part_id_t part_id, const char *name, uint32_t min_size,
		uint32_t max_size, uint8_t priority, bool valid);

int ocf_mngt_cache_lock_init(ocf_cache_t cache);
void ocf_mngt_cache_lock_deinit(ocf_cache_t cache);

bool ocf_mngt_cache_is_locked(ocf_cache_t cache);

void __set_cleaning_policy(ocf_cache_t cache,
		ocf_cleaning_t new_cleaning_policy);

void ocf_mngt_continue_pipeline_on_zero_refcnt(struct env_refcnt *refcnt,
		ocf_pipeline_t pipeline);

#endif /* __OCF_MNGT_COMMON_H__ */
