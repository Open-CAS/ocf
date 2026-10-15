/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_LAYOUT_CORE_H__
#define __METADATA_LAYOUT_CORE_H__

#include "ocf/ocf.h"
#include "superblock.h"

struct ocf_metadata_uuid {
	uint32_t size;
	uint8_t data[OCF_VOLUME_UUID_MAX_SIZE];
} __packed;

struct ocf_core_meta_config {
	char name[OCF_CORE_NAME_SIZE];

	uint8_t type;

	/* Core sequence number used to correlate cache lines with cores
	 * when recovering from atomic device
	 */
	ocf_seq_no_t seq_no;

	/* Sequential cutoff threshold (in bytes) */
	env_atomic seq_cutoff_threshold;

	/* Sequential cutoff policy */
	env_atomic seq_cutoff_policy;

	/* Sequence detector stream promotion request count */
	env_atomic seq_detect_promotion_count;

	/* Sequence detector stream promotion threshold (in bytes) */
	env_atomic seq_detect_promotion_threshold;

	/* core object size in bytes */
	uint64_t length;

	uint8_t user_data[OCF_CORE_USER_DATA_SIZE];
};

struct ocf_core_meta_runtime {
	/* Number of blocks from that objects that currently are cached
	 * on the caching device.
	 */
	env_atomic cached_clines;
	env_atomic dirty_clines;
	env_atomic initial_dirty_clines;

	env_atomic64 dirty_since;

	struct {
		/* clines within lru list (?) */
		env_atomic cached_clines;
		/* dirty clines assigned to this specific partition within
		 * cache device
		 */
		env_atomic dirty_clines;
	} part_counters[OCF_USER_IO_CLASS_MAX];
};

/**
 * @brief Validity of core config fields
 *
 * Each field tells whether the core config field of the same name holds
 * a valid value. Fields are listed in the order of checking. Config of core
 * which is not in use (according to superblock valid core bitmap) is valid
 * as a whole.
 */
struct ocf_core_meta_config_validity {
	bool name;
	bool seq_no;
	bool seq_cutoff_threshold;
	bool seq_cutoff_policy;
	bool seq_detect_promotion_count;
	bool seq_detect_promotion_threshold;
};

/**
 * @brief Validate core config
 *
 * @param superblock - Superblock config
 * @param core_id - Core id
 * @param core_config - Core config of given core
 * @param valid - Validity of core config fields
 */
void ocf_core_meta_config_validate(
		const struct ocf_superblock_config *superblock,
		ocf_core_id_t core_id,
		const struct ocf_core_meta_config *core_config,
		struct ocf_core_meta_config_validity *valid);

/**
 * @brief Validity of core configs as a whole
 */
struct ocf_cores_validity {
	bool seq_no;
		/*!< Sequence numbers of cores in use are unique */
};

/**
 * @brief Validate core configs as a whole
 *
 * @param superblock - Superblock config
 * @param core_config - Configs of all cores
 * @param valid - Validity of core configs as a whole
 */
void ocf_cores_validate(const struct ocf_superblock_config *superblock,
		const struct ocf_core_meta_config *core_config,
		struct ocf_cores_validity *valid);

/**
 * @brief Validity of core uuid fields
 *
 * Uuid of core which is not in use (according to superblock valid core
 * bitmap) is valid as a whole.
 */
struct ocf_metadata_uuid_validity {
	bool size;
};

/**
 * @brief Validate core uuid
 *
 * @param superblock - Superblock config
 * @param core_id - Core id
 * @param uuid - Core uuid
 * @param valid - Validity of core uuid fields
 */
void ocf_metadata_uuid_validate(
		const struct ocf_superblock_config *superblock,
		ocf_core_id_t core_id,
		const struct ocf_metadata_uuid *uuid,
		struct ocf_metadata_uuid_validity *valid);

#endif /* __METADATA_LAYOUT_CORE_H__ */
