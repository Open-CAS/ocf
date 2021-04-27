/*
 * Copyright(c) 2012-2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_RAW_PERSISTENT_H__
#define __METADATA_RAW_PERSISTENT_H__

int raw_persistent_init(ocf_cache_t cache,
		ocf_flush_page_synch_t lock_page_pfn,
		ocf_flush_page_synch_t unlock_page_pfn,
		struct ocf_metadata_raw *raw);

int raw_persistent_deinit(ocf_cache_t cache, struct ocf_metadata_raw *raw);

void raw_persistent_load_all(ocf_cache_t cache, struct ocf_metadata_raw *raw,
		ocf_metadata_end_t cmpl, void *priv);

#endif /* __METADATA_RAW_PERSISTENT_H__ */
