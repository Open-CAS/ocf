/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"

#include "metadata.h"
#include "metadata_hash.h"
#include "metadata_io.h"
#include "../ocf_priv.h"
#include "../utils/utils_io.h"
#include "../utils/utils_cache_line.h"

#define OCF_DEBUG_TAG "meta.hash"
#define OCF_DEBUG 0
#include "../ocf_debug.h"

int ocf_metadata_init(struct ocf_cache *cache,
		ocf_cache_line_size_t cache_line_size)
{
	struct ocf_metadata_iface *iface = (struct ocf_metadata_iface *)
			&cache->metadata.iface;
	int ret;

	OCF_DEBUG_CACHE_TRACE(cache);

	ENV_BUG_ON(cache->metadata.iface_priv);

	ret = ocf_metadata_io_init(cache);
	if (ret)
		return ret;

	*iface = *metadata_hash_get_iface();
	ret = cache->metadata.iface.init(cache, cache_line_size);
	if (ret)
		ocf_metadata_io_deinit(cache);

	return ret;
}

int ocf_metadata_init_variable_size(struct ocf_cache *cache, uint64_t device_size,
		ocf_cache_line_size_t cache_line_size,
		ocf_metadata_layout_t layout)
{
	OCF_DEBUG_CACHE_TRACE(cache);
	return cache->metadata.iface.init_variable_size(cache, device_size,
			cache_line_size, layout);
}

void ocf_metadata_init_freelist_partition(struct ocf_cache *cache)
{
	OCF_DEBUG_CACHE_TRACE(cache);
	cache->metadata.iface.layout_iface->init_freelist(cache);
}

void ocf_metadata_init_hash_table(struct ocf_cache *cache)
{
	OCF_DEBUG_CACHE_TRACE(cache);
	cache->metadata.iface.init_hash_table(cache);
}

void ocf_metadata_deinit(struct ocf_cache *cache)
{
	OCF_DEBUG_CACHE_TRACE(cache);

	if (cache->metadata.iface.deinit) {
		cache->metadata.iface.deinit(cache);
	}

	ocf_metadata_io_deinit(cache);
}

void ocf_metadata_deinit_variable_size(struct ocf_cache *cache)
{
	OCF_DEBUG_CACHE_TRACE(cache);

	if (cache->metadata.iface.deinit_variable_size)
		cache->metadata.iface.deinit_variable_size(cache);
}

size_t ocf_metadata_size_of(struct ocf_cache *cache)
{
	return cache->metadata.iface.size_of(cache);
}

void ocf_metadata_error(struct ocf_cache *cache)
{
	if (cache->device->metadata_error == 0)
		ocf_cache_log(cache, log_err, "Metadata Error\n");

	env_bit_clear(ocf_cache_state_running, &cache->cache_state);
	cache->device->metadata_error = -1;
}

ocf_cache_line_t ocf_metadata_get_pages_count(struct ocf_cache *cache)
{
	return cache->metadata.iface.pages(cache);
}

ocf_cache_line_t
ocf_metadata_get_cachelines_count(struct ocf_cache *cache)
{
	return cache->metadata.iface.cachelines(cache);
}

int ocf_metadata_flush_all(struct ocf_cache *cache)
{
	int result;

	OCF_METADATA_LOCK_WR();
	result = cache->metadata.iface.flush_all(cache);
	OCF_METADATA_UNLOCK_WR();
	return result;
}

void ocf_metadata_flush(struct ocf_cache *cache, ocf_cache_line_t line)
{
	cache->metadata.iface.flush(cache, line);
}

int ocf_metadata_load_all(struct ocf_cache *cache)
{
	int result;

	OCF_METADATA_LOCK_WR();
	result = cache->metadata.iface.load_all(cache);
	OCF_METADATA_UNLOCK_WR();
	return result;
}

int ocf_metadata_load_recovery(struct ocf_cache *cache)
{
	return cache->metadata.iface.load_recovery(cache);
}

void ocf_metadata_flush_mark(struct ocf_cache *cache, struct ocf_request *req,
		uint32_t map_idx, int to_state, uint8_t start, uint8_t stop)
{
	cache->metadata.iface.flush_mark(cache, req, map_idx, to_state,
			start, stop);
}

void ocf_metadata_flush_do_asynch(struct ocf_cache *cache,
		struct ocf_request *req, ocf_req_end_t complete)
{
	cache->metadata.iface.flush_do_asynch(cache, req, complete);
}

struct ocf_metadata_read_sb_ctx;

typedef void (*ocf_metadata_read_sb_end_t)(
		struct ocf_metadata_read_sb_ctx *context);

struct ocf_metadata_read_sb_ctx {
	struct ocf_superblock_config superblock;
	ocf_metadata_read_sb_end_t cmpl;
	ocf_ctx_t ctx;
	void *priv1;
	void *priv2;
	int error;
};

static void ocf_metadata_read_sb_complete(struct ocf_io *io, int error)
{
	struct ocf_metadata_read_sb_ctx *context = io->priv1;
	ctx_data_t *data = ocf_io_get_data(io);

	if (!error) {
		/* Read data from data into super block buffer */
		ctx_data_rd_check(context->ctx, &context->superblock, data,
				sizeof(context->superblock));
	}


	context->error = error;
	context->cmpl(context);

	ctx_data_free(context->ctx, data);
	ocf_io_put(io);
	env_free(context);
}

static int ocf_metadata_read_sb(ocf_ctx_t ctx, ocf_volume_t volume,
		ocf_metadata_read_sb_end_t cmpl, void *priv1, void *priv2)
{
	struct ocf_metadata_read_sb_ctx *context;
	size_t sb_pages = BYTES_TO_PAGES(sizeof(context->superblock));
	ctx_data_t *data;
	struct ocf_io *io;
	int result = 0;

	/* Allocate memory for first page of super block */
	context = env_zalloc(sizeof(*context), ENV_MEM_NORMAL);
	if (!context) {
		ocf_log(ctx, log_err, "Memory allocation error");
		return -ENOMEM;
	}

	context->cmpl = cmpl;
	context->ctx = ctx;
	context->priv1 = priv1;
	context->priv2 = priv2;

	/* Allocate resources for IO */
	io = ocf_volume_new_io(volume);
	if (!io) {
		ocf_log(ctx, log_err, "Memory allocation error");
		result = -ENOMEM;
		goto err_io;
	}

	data = ctx_data_alloc(ctx, sb_pages);
	if (!data) {
		ocf_log(ctx, log_err, "Memory allocation error");
		result = -ENOMEM;
		goto err_data;
	}

	/*
	 * Read first page of cache device in order to recover metadata
	 * properties
	 */
	result = ocf_io_set_data(io, data, 0);
	if (result) {
		ocf_log(ctx, log_err, "Metadata IO configuration error\n");
		result = -EIO;
		goto err_set_data;
	}

	ocf_io_configure(io, 0, sb_pages * PAGE_SIZE, OCF_READ, 0, 0);

	ocf_io_set_cmpl(io, context, NULL, ocf_metadata_read_sb_complete);
	ocf_volume_submit_io(io);

	return 0;

err_set_data:
	ctx_data_free(ctx, data);
err_data:
	ocf_io_put(io);
err_io:
	env_free(context);
	return result;
}

static void ocf_metadata_load_properties_cmpl(
		struct ocf_metadata_read_sb_ctx *context)
{
	struct ocf_metadata_load_properties properties;
	struct ocf_superblock_config *superblock = &context->superblock;
	ocf_metadata_load_properties_end_t cmpl = context->priv1;
	void *priv = context->priv2;
	ocf_ctx_t ctx = context->ctx;

	if (superblock->magic_number != CACHE_MAGIC_NUMBER) {
		ocf_log(ctx, log_info, "Cannot detect pre-existing metadata\n");
		cmpl(priv, -ENODATA, NULL);
		return;
	}

	if (METADATA_VERSION() != superblock->metadata_version) {
		ocf_log(ctx, log_err, "Metadata version mismatch!\n");
		cmpl(priv, -EBADF, NULL);
		return;
	}

	if (!ocf_cache_line_size_is_valid(superblock->line_size)) {
		ocf_log(ctx, log_err, "ERROR: Invalid cache line size!\n");
		cmpl(priv, -EINVAL, NULL);
		return;
	}

	if ((unsigned)superblock->metadata_layout >= ocf_metadata_layout_max) {
		ocf_log(ctx, log_err, "ERROR: Invalid metadata layout!\n");
		cmpl(priv, -EINVAL, NULL);
		return;
	}

	if (superblock->cache_mode >= ocf_cache_mode_max) {
		ocf_log(ctx, log_err, "ERROR: Invalid cache mode!\n");
		cmpl(priv, -EINVAL, NULL);
		return;
	}

	if (superblock->clean_shutdown > ocf_metadata_clean_shutdown) {
		ocf_log(ctx, log_err, "ERROR: Invalid shutdown status!\n");
		cmpl(priv, -EINVAL, NULL);
		return;
	}

	if (superblock->dirty_flushed > DIRTY_FLUSHED) {
		ocf_log(ctx, log_err, "ERROR: Invalid flush status!\n");
		cmpl(priv, -EINVAL, NULL);
		return;
	}

	properties.line_size = superblock->line_size;
	properties.layout = superblock->metadata_layout;
	properties.cache_mode = superblock->cache_mode;
	properties.shutdown_status = superblock->clean_shutdown;
	properties.dirty_flushed = superblock->dirty_flushed;

	cmpl(priv, 0, &properties);
}

void ocf_metadata_load_properties(ocf_volume_t volume,
		ocf_metadata_load_properties_end_t cmpl, void *priv)
{
	int result;

	OCF_DEBUG_CACHE_TRACE(volume->cache);

	result = ocf_metadata_read_sb(volume->cache->owner, volume,
			ocf_metadata_load_properties_cmpl, cmpl, priv);
	if (result)
		cmpl(priv, result, NULL);
}

static void ocf_metadata_probe_cmpl(struct ocf_metadata_read_sb_ctx *context)
{
	struct ocf_metadata_probe_status status;
	struct ocf_superblock_config *superblock = &context->superblock;
	ocf_metadata_probe_end_t cmpl = context->priv1;
	void *priv = context->priv2;

	if (superblock->magic_number != CACHE_MAGIC_NUMBER) {
		cmpl(priv, -ENODATA, NULL);
		return;
	}

	if (METADATA_VERSION() != superblock->metadata_version) {
		cmpl(priv, -EBADF, NULL);
		return;
	}

	if (superblock->clean_shutdown > ocf_metadata_clean_shutdown) {
		cmpl(priv, -EINVAL, NULL);
		return;
	}

	if (superblock->dirty_flushed > DIRTY_FLUSHED) {
		cmpl(priv, -EINVAL, NULL);
		return;
	}

	status.clean_shutdown = (superblock->clean_shutdown !=
			ocf_metadata_dirty_shutdown);
	status.cache_dirty = (superblock->dirty_flushed == DIRTY_NOT_FLUSHED);

	cmpl(priv, 0, &status);
}

void ocf_metadata_probe(ocf_ctx_t ctx, ocf_volume_t volume,
		ocf_metadata_probe_end_t cmpl, void *priv)
{
	int result;

	OCF_CHECK_NULL(ctx);
	OCF_CHECK_NULL(volume);

	result = ocf_metadata_read_sb(ctx, volume, ocf_metadata_probe_cmpl,
			cmpl, priv);
	if (result)
		cmpl(priv, result, NULL);
}
