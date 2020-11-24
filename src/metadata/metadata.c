/*
 * Copyright(c) 2012-2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"

#include "metadata.h"
#include "metadata_hash.h"
#include "metadata_io.h"
#include "../ocf_priv.h"
#include "../utils/utils_io.h"
#include "../utils/utils_cache_line.h"

#define OCF_METADATA_DEBUG 0

#if 1 == OCF_METADATA_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Metadata][Hash] %s\n", __func__)
#else
#define OCF_DEBUG_TRACE(cache)
#endif

/* TODO: temporarily still in metadata_hash.c, definition will
 be moved to this file */
int ocf_metadata_init_fixed_size(struct ocf_cache *cache,
		ocf_cache_line_size_t cache_line_size);
void ocf_metadata_deinit_fixed_size(struct ocf_cache *cache);
void ocf_metadata_query_cores(ocf_ctx_t owner, ocf_volume_t volume,
		struct ocf_volume_uuid *uuid, uint32_t count,
		ocf_metadata_query_cores_end_t cmpl, void *priv);

int ocf_metadata_init(struct ocf_cache *cache,
		ocf_cache_line_size_t cache_line_size)
{
	int ret;

	OCF_DEBUG_TRACE(cache);

	ret = ocf_metadata_init_fixed_size(cache, cache_line_size);
	if (ret) {
		ocf_metadata_io_deinit(cache);
		return ret;
	}

	ret = ocf_metadata_concurrency_init(&cache->metadata.lock);
	if (ret) {
		ocf_metadata_deinit_fixed_size(cache);

		ocf_metadata_io_deinit(cache);
		return ret;
	}

	return 0;
}

void ocf_metadata_deinit(struct ocf_cache *cache)
{
	OCF_DEBUG_TRACE(cache);

	ocf_metadata_deinit_fixed_size(cache);
	ocf_metadata_concurrency_deinit(&cache->metadata.lock);
	ocf_metadata_io_deinit(cache);
}

void ocf_metadata_error(struct ocf_cache *cache)
{
	if (cache->device->metadata_error == 0)
		ocf_cache_log(cache, log_err, "Metadata Error\n");

	env_bit_clear(ocf_cache_state_running, &cache->cache_state);
	cache->device->metadata_error = -1;
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

	ctx_data_free(context->ctx, data);
	ocf_io_put(io);

	context->error = error;
	context->cmpl(context);

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
		return -OCF_ERR_NO_MEM;
	}

	context->cmpl = cmpl;
	context->ctx = ctx;
	context->priv1 = priv1;
	context->priv2 = priv2;

	/* Allocate resources for IO */
	io = ocf_volume_new_io(volume, NULL, 0, sb_pages * PAGE_SIZE,
			OCF_READ, 0, 0);
	if (!io) {
		ocf_log(ctx, log_err, "Memory allocation error");
		result = -OCF_ERR_NO_MEM;
		goto err_io;
	}

	data = ctx_data_alloc(ctx, sb_pages);
	if (!data) {
		ocf_log(ctx, log_err, "Memory allocation error");
		result = -OCF_ERR_NO_MEM;
		goto err_data;
	}

	/*
	 * Read first page of cache device in order to recover metadata
	 * properties
	 */
	result = ocf_io_set_data(io, data, 0);
	if (result) {
		ocf_log(ctx, log_err, "Metadata IO configuration error\n");
		result = -OCF_ERR_IO;
		goto err_set_data;
	}

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
		OCF_CMPL_RET(priv, -OCF_ERR_NO_METADATA, NULL);
	}

	if (METADATA_VERSION() != superblock->metadata_version) {
		ocf_log(ctx, log_err, "Metadata version mismatch!\n");
		OCF_CMPL_RET(priv, -OCF_ERR_METADATA_VER, NULL);
	}

	if (!ocf_cache_line_size_is_valid(superblock->line_size)) {
		ocf_log(ctx, log_err, "ERROR: Invalid cache line size!\n");
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL, NULL);
	}

	if ((unsigned)superblock->metadata_layout >= ocf_metadata_layout_max) {
		ocf_log(ctx, log_err, "ERROR: Invalid metadata layout!\n");
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL, NULL);
	}

	if (superblock->cache_mode >= ocf_cache_mode_max) {
		ocf_log(ctx, log_err, "ERROR: Invalid cache mode!\n");
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL, NULL);
	}

	if (superblock->clean_shutdown > ocf_metadata_clean_shutdown) {
		ocf_log(ctx, log_err, "ERROR: Invalid shutdown status!\n");
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL, NULL);
	}

	if (superblock->dirty_flushed > DIRTY_FLUSHED) {
		ocf_log(ctx, log_err, "ERROR: Invalid flush status!\n");
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL, NULL);
	}

	properties.line_size = superblock->line_size;
	properties.layout = superblock->metadata_layout;
	properties.cache_mode = superblock->cache_mode;
	properties.shutdown_status = superblock->clean_shutdown;
	properties.dirty_flushed = superblock->dirty_flushed;
	properties.cache_name = superblock->name;

	OCF_CMPL_RET(priv, 0, &properties);
}

void ocf_metadata_load_properties(ocf_volume_t volume,
		ocf_metadata_load_properties_end_t cmpl, void *priv)
{
	int result;

	OCF_DEBUG_TRACE(cache);

	result = ocf_metadata_read_sb(volume->cache->owner, volume,
			ocf_metadata_load_properties_cmpl, cmpl, priv);
	if (result)
		OCF_CMPL_RET(priv, result, NULL);
}

static void ocf_metadata_probe_cmpl(struct ocf_metadata_read_sb_ctx *context)
{
	struct ocf_metadata_probe_status status;
	struct ocf_superblock_config *superblock = &context->superblock;
	ocf_metadata_probe_end_t cmpl = context->priv1;
	void *priv = context->priv2;

	if (superblock->magic_number != CACHE_MAGIC_NUMBER)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_METADATA, NULL);

	if (METADATA_VERSION() != superblock->metadata_version)
		OCF_CMPL_RET(priv, -OCF_ERR_METADATA_VER, NULL);

	if (superblock->clean_shutdown > ocf_metadata_clean_shutdown)
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL, NULL);

	if (superblock->dirty_flushed > DIRTY_FLUSHED)
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL, NULL);

	status.clean_shutdown = (superblock->clean_shutdown !=
			ocf_metadata_dirty_shutdown);
	status.cache_dirty = (superblock->dirty_flushed == DIRTY_NOT_FLUSHED);
	env_strncpy(status.cache_name, OCF_CACHE_NAME_SIZE, superblock->name,
			OCF_CACHE_NAME_SIZE);

	OCF_CMPL_RET(priv, 0, &status);
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
		OCF_CMPL_RET(priv, result, NULL);
}

/* completion context for query_cores */
struct ocf_metadata_query_cores_context
{
	ocf_metadata_probe_cores_end_t cmpl;
	void *priv;
};

static void ocf_metadata_query_cores_end(void *_context, int error,
		unsigned num_cores)
{
	struct ocf_metadata_query_cores_context *context = _context;

	context->cmpl(context->priv, error, num_cores);
	env_vfree(context);
}

void ocf_metadata_probe_cores(ocf_ctx_t ctx, ocf_volume_t volume,
		struct ocf_volume_uuid *uuids, uint32_t uuids_count,
		ocf_metadata_probe_cores_end_t cmpl, void *priv)
{
	struct ocf_metadata_query_cores_context *context;

	context = env_vzalloc(sizeof(*context));
	if (!context)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM, 0);

	context->cmpl = cmpl;
	context->priv = priv;

	ocf_metadata_query_cores(ctx, volume, uuids, uuids_count,
			ocf_metadata_query_cores_end, context);
}


