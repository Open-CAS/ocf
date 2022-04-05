/*
 * Copyright(c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

uint64_t ocf_get_metadata_segment_start_page(ocf_cache_t cache, int segment);
uint64_t ocf_get_metadata_segment_page_count(ocf_cache_t cache, int segment);
uint64_t ocf_get_metadata_segment_elems_count(ocf_cache_t cache, int segment);
uint64_t ocf_get_metadata_segment_elems_per_page(ocf_cache_t cache, int segment);
uint64_t ocf_get_metadata_segment_elem_size(ocf_cache_t cache, int segment);
bool ocf_get_metadata_segment_is_flapped(ocf_cache_t cache, int segment);
