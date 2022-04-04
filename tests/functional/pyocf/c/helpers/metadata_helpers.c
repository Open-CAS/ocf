/*
 * Copyright(c) 2022-2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf_io.h"
#include "ocf/ocf_cache.h"
#include "../src/ocf/ocf_cache_priv.h"
#include "../src/ocf/metadata/metadata_raw.h"
#include "../src/ocf/metadata/metadata_internal.h"

// get collision metadata segment start and size (excluding padding)
uint64_t ocf_get_collision_start_page_helper(ocf_cache_t cache)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[metadata_segment_collision];

	return raw->ssd_pages_offset;
}

uint64_t ocf_get_collision_page_count_helper(ocf_cache_t cache)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_metadata_raw *raw = &ctrl->raw_desc[metadata_segment_collision];

	return raw->ssd_pages;
}
