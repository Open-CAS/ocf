/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_SUPERBLOCK_H__
#define __METADATA_SUPERBLOCK_H__

#include <ocf/ocf_def.h>

#define CACHE_MAGIC_NUMBER	0x187E1CA6

/**
 * @brief OCF cache metadata configuration superblock
 */
struct ocf_superblock_config {
	/** WARNING: Metadata probe disregards metadata version when
	 * checking if the cache is dirty - position of next two fields
	 * shouldn't change!! */
	uint8_t clean_shutdown;
	uint8_t dirty_flushed;
	uint32_t magic_number;

	uint32_t metadata_version;

	/* Currently set cache mode */
	ocf_cache_mode_t cache_mode;

	char name[OCF_CACHE_NAME_SIZE];

	ocf_cache_line_t cachelines;
	uint32_t valid_parts_no;

	ocf_cache_line_size_t line_size;
	ocf_metadata_layout_t metadata_layout;
	uint32_t core_count;

	unsigned long valid_core_bitmap[(OCF_CORE_MAX /
			(sizeof(unsigned long) * 8)) + 1];

	ocf_cleaning_t cleaning_policy_type;
	struct cleaning_policy_config cleaning[CLEANING_POLICY_TYPE_MAX];

	ocf_promotion_t promotion_policy_type;
	struct promotion_policy_config promotion[PROMOTION_POLICY_TYPE_MAX];

	ocf_eviction_t eviction_policy_type;

	/* Current core sequence number */
	ocf_core_id_t curr_core_seq_no;

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

static inline void ocf_metadata_set_shutdown_status(ocf_cache_t cache,
		enum ocf_metadata_shutdown_status shutdown_status,
		ocf_metadata_end_t cmpl, void *priv)
{
	cache->metadata.iface.set_shutdown_status(cache, shutdown_status,
			cmpl, priv);
}

static inline void ocf_metadata_load_superblock(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	cache->metadata.iface.load_superblock(cache, cmpl, priv);
}

static inline void ocf_metadata_flush_superblock(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	cache->metadata.iface.flush_superblock(cache, cmpl, priv);
}

#endif /* METADATA_SUPERBLOCK_H_ */
