/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_CORE_H__
#define __METADATA_CORE_H__

#include "ocf/ocf.h"

struct ocf_metadata_uuid {
	uint32_t size;
	uint8_t data[OCF_VOLUME_UUID_MAX_SIZE];
} __packed;

struct ocf_core_meta_config {
	char name[OCF_CORE_NAME_SIZE];

	uint8_t type;

	/* This bit means that object was saved in cache metadata */
	uint32_t valid : 1;

	/* Core sequence number used to correlate cache lines with cores
	 * when recovering from atomic device */
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

void ocf_metadata_get_core_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_core_id_t *core_id,
		uint64_t *core_line);

void ocf_metadata_set_core_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_core_id_t core_id,
		uint64_t core_line);

ocf_core_id_t ocf_metadata_get_core_id(
		struct ocf_cache *cache, ocf_cache_line_t line);

struct ocf_metadata_uuid *ocf_metadata_get_core_uuid(
		struct ocf_cache *cache, ocf_core_id_t core_id);

void ocf_metadata_get_core_and_part_id(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_core_id_t *core_id, ocf_part_id_t *part_id);

#endif /* METADATA_CORE_H_ */
