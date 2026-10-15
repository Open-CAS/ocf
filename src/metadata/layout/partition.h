/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies Co., Ltd.
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_LAYOUT_PARTITION_H__
#define __METADATA_LAYOUT_PARTITION_H__

#include "ocf/ocf.h"
#include "lru.h"
#include "cleaning_policy.h"
#include "superblock.h"

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

/**
 * @brief Validity of user partition config fields
 *
 * Each field tells whether the partition config field of the same name
 * holds a valid value. Fields are listed in the order of checking.
 */
struct ocf_user_part_config_validity {
	bool name;
	bool min_size;
		/*!< Min size does not exceed max size */
	bool max_size;
	bool priority;
	bool cache_mode;
};

/**
 * @brief Validate user partition config
 *
 * @param part_config - Partition config
 * @param valid - Validity of partition config fields
 */
void ocf_user_part_config_validate(
		const struct ocf_user_part_config *part_config,
		struct ocf_user_part_config_validity *valid);

/**
 * @brief Validity of user partition configs as a whole
 */
struct ocf_user_parts_validity {
	bool valid_parts_no;
		/*!< Number of valid partitions matches superblock */
	bool min_size;
		/*!< Sum of min sizes of valid partitions does not exceed
		 * PARTITION_SIZE_MAX
		 */
};

/**
 * @brief Validate user partition configs as a whole
 *
 * @param superblock - Superblock config
 * @param part_config - Configs of all user partitions
 * @param valid - Validity of user partition configs as a whole
 */
void ocf_user_parts_validate(
		const struct ocf_superblock_config *superblock,
		const struct ocf_user_part_config *part_config,
		struct ocf_user_parts_validity *valid);

#endif /* __METADATA_LAYOUT_PARTITION_H__ */
