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

#define OCF_METADATA_DEBUG 0

#if 1 == OCF_METADATA_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Metadata][Hash] %s\n", __func__)
#else
#define OCF_DEBUG_TRACE(cache)
#endif

int ocf_metadata_init(struct ocf_cache *cache,
		ocf_cache_line_size_t cache_line_size)
{
	struct ocf_metadata_iface *iface = (struct ocf_metadata_iface *)
			&cache->metadata.iface;
	int ret;

	OCF_DEBUG_TRACE(cache);

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
	OCF_DEBUG_TRACE(cache);
	return cache->metadata.iface.init_variable_size(cache, device_size,
			cache_line_size, layout);
}

void ocf_metadata_init_freelist_partition(struct ocf_cache *cache)
{
	OCF_DEBUG_TRACE(cache);
	cache->metadata.iface.layout_iface->init_freelist(cache);
}

void ocf_metadata_init_hash_table(struct ocf_cache *cache)
{
	OCF_DEBUG_TRACE(cache);
	cache->metadata.iface.init_hash_table(cache);
}

void ocf_metadata_deinit(struct ocf_cache *cache)
{
	OCF_DEBUG_TRACE(cache);

	if (cache->metadata.iface.deinit) {
		cache->metadata.iface.deinit(cache);
	}

	ocf_metadata_io_deinit(cache);
}

void ocf_metadata_deinit_variable_size(struct ocf_cache *cache)
{
	OCF_DEBUG_TRACE(cache);

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

void ocf_metadata_flush_mark(struct ocf_cache *cache, struct ocf_request *rq,
		uint32_t map_idx, int to_state, uint8_t start, uint8_t stop)
{
	cache->metadata.iface.flush_mark(cache, rq, map_idx, to_state,
			start, stop);
}

void ocf_metadata_flush_do_asynch(struct ocf_cache *cache,
		struct ocf_request *rq, ocf_end_t complete)
{
	cache->metadata.iface.flush_do_asynch(cache, rq, complete);
}

static inline int ocf_metadata_check_properties(void)
{
	uint32_t field_offset;

	/* Because metadata basic properties are on the beginning of super block
	 * read/write only first page of supper block.
	 *
	 * For safety reason check if offset of metadata properties are in first
	 * page of super block.
	 *
	 * Maybe in future super block fields order may be changed and metadata
	 * variant may go out first page of super block
	 */

	field_offset = offsetof(struct ocf_superblock_config, line_size);
	ENV_BUG_ON(field_offset >= PAGE_SIZE);

	/* The same checking for magic number */
	field_offset = offsetof(struct ocf_superblock_config, magic_number);
	ENV_BUG_ON(field_offset >= PAGE_SIZE);

	/* The same checking for IO interface type */
	field_offset = offsetof(struct ocf_superblock_config, cache_mode);
	ENV_BUG_ON(field_offset >= PAGE_SIZE);

	/* And the same for version location within superblock structure */
	field_offset = offsetof(struct ocf_superblock_config, metadata_version);
	ENV_BUG_ON(field_offset >= PAGE_SIZE);

	return 0;
}

static int ocf_metadata_read_properties(ocf_ctx_t ctx, ocf_data_obj_t cache_obj,
		struct ocf_superblock_config *superblock)
{
	ctx_data_t *data;
	struct ocf_io *io;
	int result = 0;

	if (ocf_metadata_check_properties())
		return -EINVAL;

	/* Allocate resources for IO */
	io = ocf_dobj_new_io(cache_obj);
	data = ctx_data_alloc(ctx, 1);

	/* Check allocation result */
	if (!io || !data) {
		ocf_log(ctx, log_err, "Memory allocation error");
		result = -ENOMEM;
		goto out;
	}

	/*
	 * Read first page of cache device in order to recover metadata
	 * properties
	 */
	result = ocf_io_set_data(io, data, 0);
	if (result) {
		ocf_log(ctx, log_err, "Metadata IO configuration error\n");
		result = -EIO;
		goto out;
	}
	ocf_io_configure(io, 0, PAGE_SIZE, OCF_READ, 0, 0);
	result = ocf_submit_io_wait(io);
	if (result) {
		ocf_log(ctx, log_err, "Metadata IO request submit error\n");
		result = -EIO;
		goto out;
	}

	/* Read data from data into super block buffer */
	ctx_data_rd_check(ctx, superblock, data,
			PAGE_SIZE);

out:
	if (io)
		ocf_io_put(io);
	ctx_data_free(ctx, data);

	return result;
}

/**
 * @brief function loads individual properties from metadata set
 * @param cache_obj object from which to load metadata
 * @param variant - field to which save metadata variant; if NULL,
 *	metadata variant won't be read.
 * @param cache mode; if NULL is passed it won't be read
 * @param shutdown_status - dirty shutdown or clean shutdown
 * @param dirty_flushed - if all dirty data was flushed prior to closing
 *	the cache
 * @return 0 upon successful completion
 */
int ocf_metadata_load_properties(ocf_data_obj_t cache_obj,
		ocf_cache_line_size_t *line_size,
		ocf_metadata_layout_t *layout,
		ocf_cache_mode_t *cache_mode,
		enum ocf_metadata_shutdown_status *shutdown_status,
		uint8_t *dirty_flushed)
{
	struct ocf_superblock_config *superblock;
	int err_value = 0;

	/* Allocate first page of super block */
	superblock = env_zalloc(PAGE_SIZE, ENV_MEM_NORMAL);
	if (!superblock) {
		ocf_cache_log(cache_obj->cache, log_err,
				"Allocation memory error");
		return -ENOMEM;
	}

	OCF_DEBUG_TRACE(cache);

	err_value = ocf_metadata_read_properties(cache_obj->cache->owner,
			cache_obj, superblock);
	if (err_value)
		goto ocf_metadata_load_variant_ERROR;

	if (superblock->magic_number != CACHE_MAGIC_NUMBER) {
		err_value = -ENODATA;
		ocf_cache_log(cache_obj->cache, log_info,
				"Can not detect pre-existing metadata\n");
		goto ocf_metadata_load_variant_ERROR;
	}

	if (METADATA_VERSION() != superblock->metadata_version) {
		err_value = -EBADF;
		ocf_cache_log(cache_obj->cache, log_err,
				"Metadata version mismatch!\n");
		goto ocf_metadata_load_variant_ERROR;
	}

	if (line_size) {
		if (ocf_cache_line_size_is_valid(superblock->line_size)) {
			*line_size = superblock->line_size;
		} else {
			err_value = -EINVAL;
			ocf_cache_log(cache_obj->cache, log_err,
					"ERROR: Invalid cache line size!\n");
		}
	}

	if (layout) {
		if (superblock->metadata_layout >= ocf_metadata_layout_max ||
				superblock->metadata_layout < 0) {
			err_value = -EINVAL;
			ocf_cache_log(cache_obj->cache, log_err,
					"ERROR: Invalid metadata layout!\n");
		} else {
			*layout = superblock->metadata_layout;
		}
	}

	if (cache_mode) {
		if (superblock->cache_mode < ocf_cache_mode_max) {
			*cache_mode = superblock->cache_mode;
		} else {
			ocf_cache_log(cache_obj->cache, log_err,
					"ERROR: Invalid cache mode!\n");
			err_value = -EINVAL;
		}
	}

	if (shutdown_status != NULL) {
		if (superblock->clean_shutdown <= ocf_metadata_clean_shutdown) {
			*shutdown_status = superblock->clean_shutdown;
		} else {
			ocf_cache_log(cache_obj->cache, log_err,
				"ERROR: Invalid shutdown status!\n");
			err_value = -EINVAL;
		}
	}

	if (dirty_flushed != NULL) {
		if (superblock->dirty_flushed <= DIRTY_FLUSHED) {
			*dirty_flushed = superblock->dirty_flushed;
		} else {
			ocf_cache_log(cache_obj->cache, log_err,
					"ERROR: Invalid flush status!\n");
			err_value = -EINVAL;
		}
	}

ocf_metadata_load_variant_ERROR:

	env_free(superblock);
	return err_value;
}

int ocf_metadata_probe(ocf_ctx_t ctx, ocf_data_obj_t cache_obj,
		bool *clean_shutdown, bool *cache_dirty)
{
	struct ocf_superblock_config *superblock;
	int result = 0;

	OCF_CHECK_NULL(ctx);
	OCF_CHECK_NULL(cache_obj);

	/* Allocate first page of super block */
	superblock = env_zalloc(PAGE_SIZE, ENV_MEM_NORMAL);
	if (!superblock) {
		ocf_log(ctx, log_err, "Allocation memory error");
		return -ENOMEM;
	}

	OCF_DEBUG_TRACE(cache);

	result = ocf_metadata_read_properties(ctx, cache_obj, superblock);
	if (result)
		goto ocf_metadata_probe_END;

	if (superblock->magic_number != CACHE_MAGIC_NUMBER) {
		result = -ENODATA;
		goto ocf_metadata_probe_END;
	}

	if (clean_shutdown != NULL) {
		*clean_shutdown = (superblock->clean_shutdown !=
				ocf_metadata_dirty_shutdown);
	}

	if (cache_dirty != NULL)
		*cache_dirty = (superblock->dirty_flushed == DIRTY_NOT_FLUSHED);

	if (METADATA_VERSION() != superblock->metadata_version)
		result = -EBADF;

ocf_metadata_probe_END:

	env_free(superblock);
	return result;
}

