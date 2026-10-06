/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies Co., Ltd.
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_PARTITION_H__
#define __METADATA_PARTITION_H__

#include "ocf/ocf.h"
#include "metadata_lru.h"
#include "metadata_cleaning_policy.h"

#define PARTITION_UNSPECIFIED		((ocf_part_id_t)-1)
#define PARTITION_FREELIST		(OCF_USER_IO_CLASS_MAX + 1)
#define PARTITION_FREE_DETACHED		(OCF_USER_IO_CLASS_MAX + 2)
#define PARTITION_SIZE_MIN		0
#define PARTITION_SIZE_MAX		100

#define OCF_NUM_PARTITIONS (OCF_USER_IO_CLASS_MAX + 3)

struct ocf_user_part_config {
	char name[OCF_IO_CLASS_NAME_MAX];
	uint32_t min_size;
	uint32_t max_size;
	struct {
		uint8_t valid : 1;
		uint8_t added : 1;
		uint8_t eviction : 1;
			/*!< This bits is setting during partition sorting,
			* and means that can evict from this partition
			*/
	} flags;
	int16_t priority;
	ocf_cache_mode_t cache_mode;
};

struct ocf_part_runtime {
	env_atomic curr_size;
	env_atomic evict_counter;
	struct ocf_lru_part_meta lru[OCF_NUM_LRU_LISTS];
	struct cleaning_policy clean_pol;
};

ocf_part_id_t ocf_metadata_get_partition_id(struct ocf_cache *cache,
		ocf_cache_line_t line);

void ocf_metadata_set_partition_id(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_part_id_t part_id);

#endif /* __METADATA_PARTITION_H__ */
