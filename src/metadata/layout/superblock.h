/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_LAYOUT_SUPERBLOCK_H__
#define __METADATA_LAYOUT_SUPERBLOCK_H__

#include "ocf/ocf.h"
#include "../../ocf_def_priv.h"
#include "segment_id.h"
#include "cleaning_policy.h"
#include "promotion_policy.h"
#include "prefetch_policy.h"

#define CACHE_MAGIC_NUMBER	0x187E1CA6

/**
 * @brief Metadata shutdown status
 */
enum ocf_metadata_shutdown_status {
	ocf_metadata_dirty_shutdown = 0, /*!< Dirty OCF shutdown*/
	ocf_metadata_clean_shutdown = 1, /*!< OCF shutdown graceful*/
};

/**
 * @brief OCF cache metadata configuration superblock
 *
 * The first 12 bytes of superblock do not change between verions.
 * These fields are used by metadata probe to recognize OCF metadata
 * and identify metadata version and status.
 * The layout is following:
 * 0:7   | clean shutdown status
 * 8:15  | dirty metadata present
 * 16:31 | padding; kept for historic reasons; zeroed
 * 32:63 | OCF magic number; must be 0x187E1CA6
 * 64:95 | OCF metadata version
 *
 * The remaining fields can should be accessed only after confirming
 * correct magic and metadata version.
 */
struct ocf_superblock_config {
	/* Superblock header */
	struct {
		uint8_t clean_shutdown;
		uint8_t dirty_flushed;
		uint16_t _padding;
		uint32_t magic_number;
		uint32_t metadata_version;
	};

	/* Identity of the adapter */
	char adapter_name[OCF_ADAPTER_NAME_SIZE];
	uint32_t adapter_version;

	bool metadata_4k_mode;

	unsigned flapping_idx;

	/* Currently set cache mode */
	ocf_cache_mode_t cache_mode;

	char name[OCF_CACHE_NAME_SIZE];

	ocf_cache_line_t cachelines;
	uint32_t valid_parts_no;

	ocf_cache_line_size_t line_size;
	uint32_t core_count;

	/* Current core sequence number */
	ocf_core_id_t curr_core_seq_no;

	unsigned long valid_core_bitmap[OCF_DIV_ROUND_UP_STATIC(OCF_CORE_NUM,
			sizeof(unsigned long) * 8)];

	bool cleaner_disabled;
	ocf_cleaning_t cleaning_policy_type;
	struct cleaning_policy_config cleaning[CLEANING_POLICY_TYPE_MAX];

	ocf_promotion_t promotion_policy_type;
	struct promotion_policy_config promotion[PROMOTION_POLICY_TYPE_MAX];

	ocf_pf_mask_t prefetch_mask;
	struct prefetch_policy_config prefetch[PREFETCH_POLICY_TYPE_MAX];

	/*
	 * Checksum for each metadata region.
	 * This field has to be the last one!
	 */
	uint32_t checksum[metadata_segment_max];
};

/**
 * @brief OCF cache metadata runtime superblock
 */
struct ocf_superblock_runtime {
	uint32_t cleaning_thread_access;
};

#endif /* __METADATA_LAYOUT_SUPERBLOCK_H__ */
