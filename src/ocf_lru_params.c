/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ocf_cache_priv.h"
#include "ocf_lru_params.h"
#include "utils/utils_generator.h"

uint8_t lruid_to_bitreversal[OCF_NUM_LRU_LISTS];

static void ocf_lru_bitreversal_map_init(void)
{
	struct ocf_generator_bisect_state generator;
	uint32_t i;
	ocf_generator_bisect_init(&generator, OCF_NUM_LRU_LISTS, 0);

	for (i = 0; i < OCF_NUM_LRU_LISTS; i++) {
		lruid_to_bitreversal[i] = ocf_generator_bisect_next(&generator);
	}
}

ocf_cache_line_t ocf_get_cline_by_lru(ocf_cache_line_t entries,
		unsigned lru_cnt, unsigned lru_idx, uint32_t i)
{
	uint32_t portion;

	ENV_BUG_ON(lru_idx >= lru_cnt); /* This also will catch lru_cnt == 0 */

	portion = entries / lru_cnt;
	ENV_BUG_ON(i >= portion);

	return (portion * lru_idx) + i;
}

void ocf_init_lru_params(struct ocf_cache_device *device)
{
	ocf_cache_line_t entries = device->collision_table_entries;

	device->lru.portion = entries / OCF_NUM_LRU_LISTS;

	ocf_lru_bitreversal_map_init();
}
