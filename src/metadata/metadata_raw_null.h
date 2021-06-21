/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#pragma once

int raw_null_init(ocf_cache_t cache,
	ocf_flush_page_synch_t lock_page_pfn,
	ocf_flush_page_synch_t unlock_page_pfn,
	struct ocf_metadata_raw *raw);

int raw_null_deinit(ocf_cache_t cache, struct ocf_metadata_raw *raw);

size_t raw_null_size_of(ocf_cache_t cache, struct ocf_metadata_raw *raw);

uint32_t raw_null_page(struct ocf_metadata_raw *raw, uint32_t entry);

void *raw_null_access(ocf_cache_t cache, struct ocf_metadata_raw *raw, uint32_t entry);

