/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __OCF_OCF_H__
#define __OCF_OCF_H__

#include "ocf_space.h"

struct ocf_cache_device;
extern uint8_t lruid_to_bitreversal[OCF_NUM_LRU_LISTS];

#define OCF_LRU_MAX_LRU_ELEMENT_IDX 256

#define OCF_LRU_GET_LIST_INDEX(cline) \
	(lruid_to_bitreversal[cline / cache->device->lru.portion])

ocf_cache_line_t ocf_get_cline_by_lru(ocf_cache_line_t entries,
		unsigned lru_cnt, unsigned lru_idx, uint32_t i);

void ocf_init_lru_params(struct ocf_cache_device *device);

#endif  /* __OCF_OCF_H__ */
