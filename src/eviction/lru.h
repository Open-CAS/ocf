/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#ifndef __EVICTION_LRU_H__
#define __EVICTION_LRU_H__

#include "eviction.h"
#include "lru_structs.h"

void evp_lru_init_cline(struct ocf_cache *cache, ocf_cache_line_t cline);
void evp_lru_rm_cline(struct ocf_cache *cache, ocf_cache_line_t cline);
bool evp_lru_can_evict(struct ocf_cache *cache);
uint32_t evp_lru_req_clines(struct ocf_cache *cache, ocf_queue_t io_queue,
		ocf_part_id_t part_id, uint32_t cline_no);
void evp_lru_hot_cline(struct ocf_cache *cache, ocf_cache_line_t cline);
void evp_lru_init_evp(struct ocf_cache *cache, ocf_part_id_t part_id);
void evp_lru_dirty_cline(struct ocf_cache *cache, ocf_part_id_t part_id, uint32_t cline);
void evp_lru_clean_cline(struct ocf_cache *cache, ocf_part_id_t part_id, uint32_t cline);

#endif
