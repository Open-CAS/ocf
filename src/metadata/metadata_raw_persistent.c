/*
 * Copyright(c) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "metadata.h"
#include "metadata_io.h"
#include "metadata_segment_id.h"
#include "metadata_raw.h"
#include "metadata_raw_persistent.h"
#include "../utils/utils_cache_line.h"
#include "../ocf_def_priv.h"

#define OCF_METADATA_RAW_PERSISTENT_DEBUG 0

#if 1 == OCF_METADATA_RAW_PERSISTENT_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Metadata][Raw][Persistent] %s\n", __func__)

#define OCF_DEBUG_MSG(cache, msg) \
	ocf_cache_log(cache, log_info, "[Metadata][Raw][Persistent] %s - %s\n", \
			__func__, msg)

#define OCF_DEBUG_PARAM(cache, format, ...) \
	ocf_cache_log(cache, log_info, "[Metadata][Raw][Persistent] %s - "format"\n", \
			__func__, ##__VA_ARGS__)
#else
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_MSG(cache, msg)
#define OCF_DEBUG_PARAM(cache, format, ...)
#endif

struct raw_persistent_ctx {
	bool loaded;
};
int raw_persistent_init(ocf_cache_t cache,
	ocf_flush_page_synch_t lock_page_pfn,
	ocf_flush_page_synch_t unlock_page_pfn,
	struct ocf_metadata_raw *raw)
{
	size_t mem_pool_size;
	struct raw_persistent_ctx *ctx = env_vmalloc(sizeof(struct raw_persistent_ctx));

	if (!ctx)
		return -OCF_ERR_NO_MEM;

	raw->priv = ctx;

	OCF_DEBUG_TRACE(cache);

	/* Allocate memory pool for entries */
	mem_pool_size = raw->ssd_pages;
	mem_pool_size *= PAGE_SIZE;
	raw->mem_pool_limit = mem_pool_size;
	raw->mem_pool = ctx_persistent_meta_alloc(cache->owner, raw->persistent_allocator,
			mem_pool_size, raw->metadata_segment, &ctx->loaded);
	if (!raw->mem_pool) {
		env_vfree(ctx);
		return -OCF_ERR_NO_MEM;
	}

	if (!ctx->loaded)
		ENV_BUG_ON(env_memset(raw->mem_pool, mem_pool_size, 0));

	raw->lock_page = lock_page_pfn;
	raw->unlock_page = unlock_page_pfn;

	return 0;
}

int raw_persistent_deinit(ocf_cache_t cache, struct ocf_metadata_raw *raw)
{
	env_vfree(raw->priv);
	return 0;
}

void raw_persistent_load_all(ocf_cache_t cache, struct ocf_metadata_raw *raw,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct raw_persistent_ctx *ctx = raw->priv;

	if (!ctx->loaded)
		raw_ram_load_all(cache, raw, cmpl, priv);
	else
		cmpl(priv, 0);
}

