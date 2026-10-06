/*
 * Copyright(c) 2022 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf_io.h"
#include "ocf/ocf_cache.h"
#include "../src/ocf/ocf_cache_priv.h"
#include "../src/ocf/metadata/metadata_raw.h"
#include "../src/ocf/metadata/metadata_internal.h"
#include "../src/ocf/metadata/metadata_superblock.h"

uint64_t ocf_get_metadata_segment_start_page(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->layout->offset;
}

uint64_t ocf_get_metadata_segment_page_count(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->layout->pages;
}

uint64_t ocf_get_metadata_segment_elems_count(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->layout->entries;
}

uint64_t ocf_get_metadata_segment_elems_per_page(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->layout->entries_in_page;
}

uint64_t ocf_get_metadata_segment_elem_size(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	if (segment == metadata_segment_sb_config)
		return offsetof(struct ocf_superblock_config, checksum);

	return raw->layout->entry_size;
}

bool ocf_get_metadata_segment_is_flapped(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->layout->flapping;
}
