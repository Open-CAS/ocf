/*
 * Copyright(c) 2022-2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf_io.h"
#include "ocf/ocf_cache.h"
#include "../src/ocf/ocf_cache_priv.h"
#include "../src/ocf/metadata/metadata_raw.h"
#include "../src/ocf/metadata/metadata_internal.h"

uint64_t ocf_get_metadata_segment_start_page(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->ssd_pages_offset;
}

uint64_t ocf_get_metadata_segment_page_count(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->ssd_pages;
}

uint64_t ocf_get_metadata_segment_elems_count(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->entries;
}

uint64_t ocf_get_metadata_segment_elems_per_page(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->entries_in_page;
}

uint64_t ocf_get_metadata_segment_elem_size(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->entry_size;
}

bool ocf_get_metadata_segment_is_flapped(ocf_cache_t cache, int segment)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[segment];

	return raw->flapping;
}
