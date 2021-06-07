/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "metadata.h"
#include "metadata_segment_id.h"
#include "metadata_raw.h"
#include "metadata_raw_dynamic.h"
#include "metadata_io.h"
#include "../engine/cache_engine.h"
#include "../engine/engine_common.h"
#include "../utils/utils_io.h"
#include "../ocf_request.h"
#include "../ocf_def_priv.h"
#include "../ocf_priv.h"

int raw_null_init(ocf_cache_t cache,
	ocf_flush_page_synch_t lock_page_pfn,
	ocf_flush_page_synch_t unlock_page_pfn,
	struct ocf_metadata_raw *raw)
{
	return 0;
}

int raw_null_deinit(ocf_cache_t cache,
		struct ocf_metadata_raw *raw)
{
	return 0;
}


size_t raw_null_size_of(ocf_cache_t cache, struct ocf_metadata_raw *raw)
{
	return 0;
}

uint32_t raw_null_page(struct ocf_metadata_raw *raw, uint32_t entry)
{
	return 0;
}

void *raw_null_access(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, uint32_t entry)
{
	return NULL;
}

