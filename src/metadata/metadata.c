/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024-2025 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"

#include "metadata.h"
#include "metadata_bit.h"
#include "metadata_collision.h"
#include "metadata_segment_id.h"
#include "metadata_internal.h"
#include "metadata_layout.h"
#include "metadata_io.h"
#include "metadata_raw.h"
#include "metadata_segment.h"
#include "../concurrency/ocf_concurrency.h"
#include "../ocf_def_priv.h"
#include "../ocf_priv.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_io.h"
#include "../utils/utils_pipeline.h"
#include "../utils/utils_parallelize.h"


#define OCF_METADATA_DEBUG 0

#if 1 == OCF_METADATA_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Metadata] %s\n", __func__)
#define OCF_DEBUG_PARAM(cache, format, ...) \
	ocf_cache_log(cache, log_info, "[Metadata] %s - "format"\n", \
			__func__, ##__VA_ARGS__)
#else
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_PARAM(cache, format, ...)
#endif

/*
 * Calculate amount of cache lines taking into account required space for
 * metadata and set up variable size RAW containers accordingly
 */
static int ocf_metadata_calculate_variable_layout(struct ocf_cache *cache,
		struct ocf_metadata_ctrl *ctrl, uint64_t device_lines,
		ocf_cache_line_size_t line_size, bool cleaner_disabled)
{
	static bool warn;
	bool inexact;
	int result;

	result = ocf_metadata_layout_fit(&ctrl->metadata_layout, line_size,
			device_lines, cleaner_disabled, &inexact);

	if (inexact && !warn) {
		ocf_cache_log(cache, log_warn,
				"Metadata size calculation problem\n");
		warn = true;
	}

	if (result == -OCF_ERR_INVAL) {
		ocf_cache_log(cache, log_err,
				"Metadata size calculation ERROR\n");
	}

	if (result)
		return result;

	OCF_DEBUG_PARAM(cache, "Cache lines = %u",
			ctrl->metadata_layout.cachelines);

	return 0;
}

const char * const ocf_metadata_segment_names[] = {
		[metadata_segment_sb_config]		= "Super block config",
		[metadata_segment_sb_runtime]		= "Super block runtime",
		[metadata_segment_reserved]		= "Reserved",
		[metadata_segment_part_config]		= "Part config",
		[metadata_segment_part_runtime]		= "Part runtime",
		[metadata_segment_cleaning]		= "Cleaning",
		[metadata_segment_lru]			= "LRU list",
		[metadata_segment_collision]		= "Collision",
		[metadata_segment_list_info]		= "List info",
		[metadata_segment_hash]			= "Hash",
		[metadata_segment_core_config]		= "Core config",
		[metadata_segment_core_runtime]		= "Core runtime",
		[metadata_segment_core_uuid]		= "Core UUID",
};
#if 1 == OCF_METADATA_DEBUG
/*
 * Debug info functions prints metadata and raw containers information
 */
static void ocf_metadata_raw_info(struct ocf_cache *cache,
		struct ocf_metadata_ctrl *ctrl)
{
	uint64_t capacity = 0;
	uint64_t capacity_sum = 0;
	uint32_t i = 0;
	const char *unit;

	for (i = 0; i < metadata_segment_max; i++) {
		struct ocf_metadata_raw *raw = &(ctrl->raw_desc[i]);

		OCF_DEBUG_PARAM(cache, "Raw : name            = %s",
				ocf_metadata_segment_names[i]);
		OCF_DEBUG_PARAM(cache, "    : metadata type   = %u", i);
		OCF_DEBUG_PARAM(cache, "    : raw type        = %u",
				raw->raw_type);
		OCF_DEBUG_PARAM(cache, "    : entry size      = %u",
				raw->layout->entry_size);
		OCF_DEBUG_PARAM(cache, "    : entries         = %llu",
				raw->layout->entries);
		OCF_DEBUG_PARAM(cache, "    : entries in page = %u",
				raw->layout->entries_in_page);
		OCF_DEBUG_PARAM(cache, "    : page offset     = %llu",
				raw->layout->offset);
		OCF_DEBUG_PARAM(cache, "    : pages           = %llu",
				raw->layout->pages);
	}

	/* Provide capacity info */
	for (i = 0; i < metadata_segment_max; i++) {
		capacity = ocf_metadata_raw_size_of(cache,
				&(ctrl->raw_desc[i]));

		capacity_sum += capacity;

		if (capacity / MiB) {
			capacity = capacity / MiB;
			unit = "MiB";
		} else {
			unit = "KiB";
			capacity = capacity / KiB;

		}

		OCF_DEBUG_PARAM(cache, "%s capacity %llu %s",
			ocf_metadata_segment_names[i], capacity, unit);
	}
}
#else
#define ocf_metadata_raw_info(cache, ctrl)
#endif

/*
 * Deinitialize hash metadata interface
 */
void ocf_metadata_deinit_variable_size(struct ocf_cache *cache)
{

	uint32_t i = 0;

	struct ocf_metadata_ctrl *ctrl = (struct ocf_metadata_ctrl *)
			cache->metadata.priv;

	OCF_DEBUG_TRACE(cache);

	ocf_metadata_concurrency_attached_deinit(&cache->metadata.lock);

	/*
	 * De initialize RAW types
	 */
	for (i = metadata_segment_variable_size_start;
			i < metadata_segment_max; i++) {
		ocf_metadata_segment_destroy(cache, ctrl->segment[i]);
	}
	ctrl->metadata_layout.pages_variable = 0;
}

static inline void ocf_metadata_config_init(ocf_cache_t cache, size_t size)
{
	ENV_BUG_ON(!ocf_cache_line_size_is_valid(size));

	cache->metadata.line_size = size;

	OCF_DEBUG_PARAM(cache, "Cache line size = %lu, bits count = %llu, "
			"status size = %lu",
			size, ocf_line_blocks(cache),
			ocf_metadata_status_sizeof(size));
}

static void ocf_metadata_deinit_fixed_size(struct ocf_cache *cache)
{
	uint32_t i;

	struct ocf_metadata_ctrl *ctrl = (struct ocf_metadata_ctrl *)
			cache->metadata.priv;

	struct ocf_metadata_segment *superblock =
		ctrl->segment[metadata_segment_sb_config];

	for (i = 0; i < metadata_segment_fixed_size_max; i++) {
		if (i != metadata_segment_sb_config)
			ocf_metadata_segment_destroy(cache, ctrl->segment[i]);
	}

	ocf_metadata_superblock_destroy(cache, superblock);

	env_vfree(ctrl);
	cache->metadata.priv = NULL;
}

static struct ocf_metadata_ctrl *ocf_metadata_ctrl_init(
		bool metadata_volatile)
{
	struct ocf_metadata_ctrl *ctrl = NULL;
	uint32_t i = 0;

	ctrl = env_vzalloc(sizeof(*ctrl));
	if (!ctrl)
		return NULL;

	/* Initial setup of RAW containers */
	for (i = 0; i < metadata_segment_fixed_size_max; i++) {
		struct ocf_metadata_raw *raw = &ctrl->raw_desc[i];

		raw->metadata_segment = i;

		/* Default type for metadata RAW container */
		raw->raw_type = metadata_raw_type_ram;

		if (metadata_volatile) {
			raw->raw_type = metadata_raw_type_volatile;
		} else if (i == metadata_segment_core_uuid) {
			raw->raw_type = metadata_raw_type_dynamic;
		}
	}

	for (i = 0; i < metadata_segment_max; i++)
		ctrl->raw_desc[i].layout = &ctrl->metadata_layout.segment[i];

	/* Setup layout of fixed size segments */
	ocf_metadata_layout_init_fixed_size(&ctrl->metadata_layout,
			!metadata_volatile);

	return ctrl;
}

static int ocf_metadata_init_fixed_size(struct ocf_cache *cache,
		ocf_cache_line_size_t cache_line_size)
{
	struct ocf_metadata_ctrl *ctrl = NULL;
	struct ocf_metadata *metadata = &cache->metadata;
	struct ocf_core_meta_config *core_meta_config;
	struct ocf_core_meta_runtime *core_meta_runtime;
	struct ocf_user_part_config *part_config;
	struct ocf_part_runtime *part_runtime;
	struct ocf_metadata_segment *superblock;
	ocf_core_t core;
	ocf_core_id_t core_id;
	uint32_t i = 0;
	int result = 0;

	OCF_DEBUG_TRACE(cache);

	ENV_WARN_ON(metadata->priv);

	ocf_metadata_config_init(cache, cache_line_size);

	ctrl = ocf_metadata_ctrl_init(metadata->is_volatile);
	if (!ctrl)
		return -OCF_ERR_NO_MEM;
	metadata->priv = ctrl;

	result = ocf_metadata_superblock_init(
			&ctrl->segment[metadata_segment_sb_config], cache,
			&ctrl->raw_desc[metadata_segment_sb_config]);
	if (result) {
		ocf_metadata_deinit_fixed_size(cache);
		return result;
	}

	superblock = ctrl->segment[metadata_segment_sb_config];

	for (i = 0; i < metadata_segment_fixed_size_max; i++) {
		if (i == metadata_segment_sb_config)
			continue;
		result |= ocf_metadata_segment_init(
				&ctrl->segment[i],
				cache,
				&ctrl->raw_desc[i],
				NULL, NULL,
				superblock);
		if (result)
			break;
	}

	if (result) {
		ocf_metadata_deinit_fixed_size(cache);
		return result;
	}

	cache->conf_meta = METADATA_MEM_POOL(ctrl, metadata_segment_sb_config);

	/* Set partition metadata */
	part_config = METADATA_MEM_POOL(ctrl, metadata_segment_part_config);
	part_runtime = METADATA_MEM_POOL(ctrl, metadata_segment_part_runtime);

	for (i = 0; i < OCF_USER_IO_CLASS_MAX + 1; i++) {
		cache->user_parts[i].config = &part_config[i];
		cache->user_parts[i].clean_pol = &part_runtime[i].clean_pol;
		cache->user_parts[i].part.runtime = &part_runtime[i];
	}
	cache->free.runtime = &part_runtime[PARTITION_FREELIST];
	cache->free_detached.runtime = &part_runtime[PARTITION_FREE_DETACHED];

	/* Set core metadata */
	core_meta_config = METADATA_MEM_POOL(ctrl,
			metadata_segment_core_config);
	core_meta_runtime = METADATA_MEM_POOL(ctrl,
			metadata_segment_core_runtime);

	for_each_core_all(cache, core, core_id) {
		core->conf_meta = &core_meta_config[core_id];
		core->runtime_meta = &core_meta_runtime[core_id];
	}

	return 0;
}

static void ocf_metadata_flush_lock_collision_page(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, uint32_t page)

{
	ocf_collision_start_exclusive_access(&cache->metadata.lock,
			page);
}

static void ocf_metadata_flush_unlock_collision_page(
		struct ocf_cache *cache, struct ocf_metadata_raw *raw,
		uint32_t page)

{
	ocf_collision_end_exclusive_access(&cache->metadata.lock,
			page);
}

/*
 * Initialize hash metadata interface
 */
int ocf_metadata_init_variable_size(struct ocf_cache *cache,
		uint64_t device_size, ocf_cache_line_size_t line_size,
		bool cleaner_disabled)
{
	int result = 0;
	uint32_t i = 0;
	struct ocf_metadata_ctrl *ctrl = NULL;
	ocf_flush_page_synch_t lock_page, unlock_page;
	uint64_t device_lines;
	struct ocf_metadata_segment *superblock;

	OCF_DEBUG_TRACE(cache);

	ENV_WARN_ON(!cache->metadata.priv);

	ctrl = cache->metadata.priv;

	device_lines = device_size / line_size;
	if (device_lines > OCF_CACHE_LINE_MAX) {
		/* TODO: This is just a rough check. Most optimal one would be
		 * located in calculate_metadata_size. */
		ocf_cache_log(cache, log_err, "Device exceeds maximum suported size "
				"with this cache line size. Try bigger cache line size.\n");
		return -OCF_ERR_INVAL_CACHE_DEV;
	}

	if (cache->metadata.line_size != line_size)
		/* Re-initialize metadata with different cache line size */
		ocf_metadata_config_init(cache, line_size);

	/* Initial setup of dynamic size RAW containers */
	for (i = metadata_segment_variable_size_start;
			i < metadata_segment_max; i++) {
		struct ocf_metadata_raw *raw = &ctrl->raw_desc[i];

		raw->metadata_segment = i;

		/* Default type for metadata RAW container */
		raw->raw_type = metadata_raw_type_ram;

		if (cache->metadata.is_volatile) {
			raw->raw_type = metadata_raw_type_volatile;
		} else if (i == metadata_segment_collision &&
				ocf_volume_is_atomic(&cache->device->volume)) {
			raw->raw_type = metadata_raw_type_atomic;
		}
	}

	if (0 != ocf_metadata_calculate_variable_layout(cache, ctrl,
			device_lines, line_size, cleaner_disabled)) {
		ocf_cache_log(cache, log_err, "Couldn't fit metadata structure "
				"on device. Please try bigger cache device.\n");
		return -OCF_ERR_INVAL_CACHE_DEV;
	}

	OCF_DEBUG_PARAM(cache, "Metadata count pages fixed = %u",
			ctrl->metadata_layout.pages_fixed);
	OCF_DEBUG_PARAM(cache, "Metadata count pages variable = %u",
			ctrl->metadata_layout.pages_variable);
	OCF_DEBUG_PARAM(cache, "Metadata end pages = %u",
			ocf_metadata_layout_pages(&ctrl->metadata_layout));

	superblock = ctrl->segment[metadata_segment_sb_config];

	/*
	 * Initialize all dynamic size  RAW types
	 */
	for (i = metadata_segment_variable_size_start;
			i < metadata_segment_max; i++) {
		struct ocf_metadata_raw *raw = &ctrl->raw_desc[i];

		if (raw->layout->disabled)
			continue;

		if (i == metadata_segment_collision) {
			lock_page =
				ocf_metadata_flush_lock_collision_page;
			unlock_page =
				ocf_metadata_flush_unlock_collision_page;
		} else {
			lock_page = unlock_page = NULL;
		}

		result |= ocf_metadata_segment_init(
				&ctrl->segment[i],
				cache,
				raw,
				lock_page, unlock_page,
				superblock);

		if (result)
			goto finalize;
	}

	for (i = 0; i < metadata_segment_max; i++) {
		ocf_cache_log(cache, log_info, "%s offset : %llu kiB\n",
				ocf_metadata_segment_names[i],
				ctrl->raw_desc[i].layout->offset
				* PAGE_SIZE / KiB);
		if (i == metadata_segment_sb_config) {
			ocf_cache_log(cache, log_info, "%s size : %lu B\n",
				ocf_metadata_segment_names[i],
				offsetof(struct ocf_superblock_config, checksum)
				+ sizeof(((struct ocf_superblock_config *)0)
						->checksum));
		} else if (i == metadata_segment_sb_runtime) {
			ocf_cache_log(cache, log_info, "%s size : %lu B\n",
				ocf_metadata_segment_names[i],
				sizeof(struct ocf_superblock_runtime));
		} else {
			ocf_cache_log(cache, log_info, "%s size : %llu kiB\n",
					ocf_metadata_segment_names[i],
					ctrl->raw_desc[i].layout->pages
					* PAGE_SIZE / KiB);
		}
	}

finalize:
	if (result) {
		/*
		 * Hash De-Init also contains RAW deinitialization
		 */
		ocf_metadata_deinit_variable_size(cache);
		return result;
	}

	cache->device->runtime_meta = METADATA_MEM_POOL(ctrl,
			metadata_segment_sb_runtime);

	cache->device->collision_table_entries =
			ctrl->metadata_layout.cachelines;

	cache->device->hash_table_entries =
			ctrl->raw_desc[metadata_segment_hash].layout->entries;

	cache->device->metadata_offset =
			ocf_metadata_layout_pages(&ctrl->metadata_layout) *
			PAGE_SIZE;

	cache->conf_meta->cachelines = ctrl->metadata_layout.cachelines;
	cache->conf_meta->line_size = line_size;
	cache->conf_meta->cleaner_disabled = cleaner_disabled;

	ocf_metadata_raw_info(cache, ctrl);

	ocf_cache_log(cache, log_info, "Cache line size: %llu kiB\n",
			line_size / KiB);

	ocf_cache_log(cache, log_info, "Metadata size on device: %llu kiB\n",
			cache->device->metadata_offset / KiB);

	result = ocf_metadata_concurrency_attached_init(&cache->metadata.lock,
			cache, ctrl->raw_desc[metadata_segment_hash].
			layout->entries,
			(uint32_t)ctrl->raw_desc[metadata_segment_collision].
			layout->pages);
	if (result) {
		ocf_cache_log(cache, log_err, "Failed to initialize attached "
				"metadata concurrency\n");
		ocf_metadata_deinit_variable_size(cache);
		return  result;
	}

	return 0;
}

static inline void _ocf_init_collision_entry(struct ocf_cache *cache,
		ocf_cache_line_t idx)
{
	ocf_cache_line_t invalid_idx = cache->device->collision_table_entries;

	ocf_metadata_set_collision_info(cache, idx, invalid_idx, invalid_idx);
	ocf_metadata_set_core_info(cache, idx,
			OCF_CORE_NUM, ULONG_MAX);
	metadata_init_status_bits(cache, idx);
}

/*
 * Initialize collision table
 */

static int ocf_metadata_init_collision_handle(ocf_parallelize_t parallelize,
		void *priv, unsigned shard_id, unsigned shards_cnt)
{
	struct ocf_init_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_cache_line_t collision_table_entries = cache->device->collision_table_entries;
	uint32_t entry, portion, begin, end, step=0;

	portion = OCF_DIV_ROUND_UP((uint64_t)collision_table_entries, shards_cnt);
	begin = portion*shard_id;
	end = OCF_MIN(portion*(shard_id + 1), collision_table_entries);

	for (entry = begin; entry < end; entry++) {
		OCF_COND_RESCHED_DEFAULT(step);

		if (entry >= collision_table_entries)
			break;

		_ocf_init_collision_entry(cache, entry);
	}

	return 0;
}

static void ocf_metadata_init_finish(ocf_parallelize_t parallelize,
		void *priv, int error)
{
	struct ocf_init_metadata_context *context = priv;

	ocf_pipeline_next(context->pipeline);

	ocf_parallelize_destroy(parallelize);
}

void ocf_metadata_init_collision(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_init_metadata_context *context = priv;
	struct ocf_init_metadata_context *parallel_context;
	ocf_cache_t cache = context->cache;
	ocf_parallelize_t parallelize;
	int result;

	if (context->skip_collision)
		OCF_PL_NEXT_RET(pipeline);

	result = ocf_parallelize_create(&parallelize, cache,
			ocf_cache_get_queue_count(cache), sizeof(*context),
			ocf_metadata_init_collision_handle,
			ocf_metadata_init_finish, false);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);

	parallel_context = ocf_parallelize_get_priv(parallelize);

	parallel_context->pipeline = pipeline;
	parallel_context->cache = cache;

	ocf_parallelize_run(parallelize);
}

/*
 * Initialize hash table
 */
static int ocf_metadata_init_hash_table_handle(ocf_parallelize_t parallelize,
		void *priv, unsigned shard_id, unsigned shards_cnt)
{
	struct ocf_init_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;
	uint32_t hash_table_entries = cache->device->hash_table_entries;
	ocf_cache_line_t invalid_idx = cache->device->collision_table_entries;
	uint32_t entry, portion, begin, end, step=0;

	portion = OCF_DIV_ROUND_UP((uint64_t)hash_table_entries, shards_cnt);
	begin = portion*shard_id;
	end = OCF_MIN(portion*(shard_id + 1), hash_table_entries);

	for (entry = begin; entry < end; entry++) {
		OCF_COND_RESCHED_DEFAULT(step);

		if (entry >= hash_table_entries)
			break;

		ocf_metadata_set_hash(cache, entry, invalid_idx);
	}

	return 0;
}

void ocf_metadata_init_hash_table(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_init_metadata_context *context = priv;
	struct ocf_init_metadata_context *parallel_context;
	ocf_cache_t cache = context->cache;
	ocf_parallelize_t parallelize;
	int result;

	result = ocf_parallelize_create(&parallelize, cache,
			ocf_cache_get_queue_count(cache), sizeof(*context),
			ocf_metadata_init_hash_table_handle,
			ocf_metadata_init_finish, false);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);

	parallel_context = ocf_parallelize_get_priv(parallelize);

	parallel_context->pipeline = pipeline;
	parallel_context->cache = cache;

	ocf_parallelize_run(parallelize);
}

/*
 * Get amount of cache lines
 */
ocf_cache_line_t ocf_metadata_get_cachelines_count(
		struct ocf_cache *cache)
{
	struct ocf_metadata_ctrl *ctrl = NULL;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_ctrl *) cache->metadata.priv;

	return ctrl->metadata_layout.cachelines;
}

size_t ocf_metadata_size_of(struct ocf_cache *cache)
{
	uint32_t i = 0;
	size_t size = 0;
	struct ocf_metadata_ctrl *ctrl = NULL;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_ctrl *) cache->metadata.priv;

	/*
	 * Get size of all RAW metadata container
	 */
	for (i = 0; i < metadata_segment_max; i++) {
		size += ocf_metadata_raw_size_of(cache,
				&(ctrl->raw_desc[i]));
	}

	/* Get additional part of memory footprint */

	/* Cache concurrency mechnism */
	size += ocf_cache_line_concurrency_size_of(cache);

	return size;
}
/*******************************************************************************
 * RESERVED AREA
 ******************************************************************************/

uint64_t ocf_metadata_get_reserved_lba(
		struct ocf_cache *cache)
{
	struct ocf_metadata_ctrl *ctrl;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_ctrl *) cache->metadata.priv;
	return ctrl->raw_desc[metadata_segment_reserved].layout->offset *
			PAGE_SIZE;
}

/*******************************************************************************
 * FLUSH AND LOAD ALL
 ******************************************************************************/

static void ocf_metadata_flush_all_set_status_complete(
		void *priv, int error)
{
	struct ocf_metadata_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static void ocf_metadata_flush_all_set_status(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;
	enum ocf_metadata_shutdown_status shutdown_status =
			ocf_pipeline_arg_get_int(arg);

	ocf_metadata_set_shutdown_status(cache, shutdown_status,
			ocf_metadata_flush_all_set_status_complete,
			context);
}

static void ocf_metadata_flush_all_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err, "Metadata Flush ERROR\n");
		ocf_metadata_error(cache);
		goto out;
	}

	ocf_cache_log(cache, log_info, "Done saving cache state!\n");

out:
	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_arg ocf_metadata_flush_all_args[] = {
	OCF_PL_ARG_INT(metadata_segment_sb_runtime),
	OCF_PL_ARG_INT(metadata_segment_part_runtime),
	OCF_PL_ARG_INT(metadata_segment_core_runtime),
	OCF_PL_ARG_INT(metadata_segment_lru),
	OCF_PL_ARG_INT(metadata_segment_collision),
	OCF_PL_ARG_INT(metadata_segment_list_info),
	OCF_PL_ARG_INT(metadata_segment_hash),
	OCF_PL_ARG_TERMINATOR(),
};

/*
 * Predicate function checking whether disable cleaner option is set
 */
static bool ocf_check_if_cleaner_enabled(ocf_pipeline_t pipeline,
		void* priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_context *context = priv;

	return !context->cache->conf_meta->cleaner_disabled;
}

struct ocf_pipeline_properties ocf_metadata_flush_all_pipeline_props = {
	.priv_size = sizeof(struct ocf_metadata_context),
	.finish = ocf_metadata_flush_all_finish,
	.steps = {

		OCF_PL_STEP_COND_ARG_INT(ocf_check_if_cleaner_enabled,
				ocf_metadata_flush_segment,
				metadata_segment_cleaning),
		OCF_PL_STEP_FOREACH(ocf_metadata_flush_segment,
				ocf_metadata_flush_all_args),

		OCF_PL_STEP_COND_ARG_INT(ocf_check_if_cleaner_enabled,
				ocf_metadata_calculate_crc,
				metadata_segment_cleaning),
		OCF_PL_STEP_FOREACH(ocf_metadata_calculate_crc,
				ocf_metadata_flush_all_args),
		OCF_PL_STEP_ARG_INT(ocf_metadata_flush_all_set_status,
				ocf_metadata_clean_shutdown),
		OCF_PL_STEP_TERMINATOR(),
	},
};

/*
 * Flush all metadata
 */
void ocf_metadata_flush_all(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_DEBUG_TRACE(cache);

	if (cache->metadata.is_volatile) {
		/*
		 * metadata ia volatile, no need to flush anything.
		 */
		cmpl(priv, 0);
		return;
	}

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_metadata_flush_all_pipeline_props);
	if (result)
		OCF_CMPL_RET(priv, result);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->ctrl = cache->metadata.priv;

	ocf_pipeline_next(pipeline);
}

/*
 * Flush collision metadata
 */
void ocf_metadata_flush_collision(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_ctrl *ctrl;
	struct ocf_metadata_raw *raw;

	OCF_DEBUG_TRACE(cache);

	ctrl = cache->metadata.priv;
	raw = &ctrl->raw_desc[metadata_segment_collision];

	ocf_metadata_raw_flush_all(cache, raw, cmpl, priv, 0);
}

/*
 * Flush specified cache line
 */
void ocf_metadata_flush_mark(struct ocf_cache *cache,
		struct ocf_request *req, uint32_t map_idx, int to_state,
		uint8_t start, uint8_t stop)
{
	struct ocf_metadata_ctrl *ctrl = NULL;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_ctrl *) cache->metadata.priv;

	/*
	 * Mark all required metadata elements to make given metadata cache
	 * line persistent in case of recovery
	 */

	/* Collision table to get mapping cache line to HDD block */
	ocf_metadata_raw_flush_mark(cache,
			&(ctrl->raw_desc[metadata_segment_collision]),
			req, map_idx, to_state, start, stop);
}

/*
 * Flush specified cache lines asynchronously
 */
void ocf_metadata_flush_do_asynch(struct ocf_cache *cache,
		struct ocf_request *req, ocf_req_end_t complete)
{
	int result = 0;
	struct ocf_metadata_ctrl *ctrl = NULL;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_ctrl *) cache->metadata.priv;

	/*
	 * Flush all required metadata elements to make given metadata cache
	 * line persistent in case of recovery
	 */

	result |= ocf_metadata_raw_flush_do_asynch(cache, req,
			&(ctrl->raw_desc[metadata_segment_collision]),
			complete);

	if (result) {
		ocf_metadata_error(cache);
		ocf_cache_log(cache, log_err, "Metadata Flush ERROR\n");
	}
}

static void ocf_metadata_load_all_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err, "Metadata read FAILURE\n");
		ocf_metadata_error(cache);
		goto out;
	}

	ocf_cache_log(cache, log_info, "Done loading cache state\n");

out:
	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_arg ocf_metadata_load_all_args[] = {
	OCF_PL_ARG_INT(metadata_segment_core_runtime),
	OCF_PL_ARG_INT(metadata_segment_lru),
	OCF_PL_ARG_INT(metadata_segment_collision),
	OCF_PL_ARG_INT(metadata_segment_list_info),
	OCF_PL_ARG_INT(metadata_segment_hash),
	OCF_PL_ARG_TERMINATOR(),
};

struct ocf_pipeline_properties ocf_metadata_load_all_pipeline_props = {
	.priv_size = sizeof(struct ocf_metadata_context),
	.finish = ocf_metadata_load_all_finish,
	.steps = {
		OCF_PL_STEP_COND_ARG_INT(ocf_check_if_cleaner_enabled,
				ocf_metadata_load_segment,
				metadata_segment_cleaning),
		OCF_PL_STEP_FOREACH(ocf_metadata_load_segment,
				ocf_metadata_load_all_args),

		OCF_PL_STEP_COND_ARG_INT(ocf_check_if_cleaner_enabled,
				ocf_metadata_check_crc,
				metadata_segment_cleaning),
		OCF_PL_STEP_FOREACH(ocf_metadata_check_crc,
				ocf_metadata_load_all_args),
		OCF_PL_STEP_TERMINATOR(),
	},
};

/*
 * Load all metadata
 */
void ocf_metadata_load_all(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_DEBUG_TRACE(cache);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_metadata_load_all_pipeline_props);
	if (result)
		OCF_CMPL_RET(priv, result);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->ctrl = cache->metadata.priv;

	ocf_pipeline_next(pipeline);
}

static void ocf_metadata_load_recovery_legacy_finish(
		ocf_pipeline_t pipeline, void *priv, int error)
{
	struct ocf_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"Metadata read for recovery FAILURE\n");
		ocf_metadata_error(cache);
		goto out;
	}

	ocf_cache_log(cache, log_info, "Done loading cache state\n");

out:
	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_properties
ocf_metadata_load_recovery_legacy_pl_props = {
	.priv_size = sizeof(struct ocf_metadata_context),
	.finish = ocf_metadata_load_recovery_legacy_finish,
	.steps = {
		OCF_PL_STEP_ARG_INT(ocf_metadata_load_segment,
				metadata_segment_collision),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void _ocf_metadata_load_recovery_legacy(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_DEBUG_TRACE(cache);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_metadata_load_recovery_legacy_pl_props);
	if (result)
		OCF_CMPL_RET(priv, result);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->ctrl = cache->metadata.priv;

	ocf_pipeline_next(pipeline);
}

static ocf_core_id_t _ocf_metadata_find_core_by_seq(
		struct ocf_cache *cache, ocf_seq_no_t seq_no)
{
	ocf_core_t core;
	ocf_core_id_t core_id;

	if (seq_no == OCF_SEQ_NO_INVALID)
		return OCF_CORE_ID_INVALID;

	for_each_core_all(cache, core, core_id) {
		if (core->conf_meta->seq_no == seq_no)
			break;
	}

	return core_id;
}

static void ocf_metadata_load_atomic_metadata_complete(
		ocf_cache_t cache, void *priv, int error)
{
	struct ocf_metadata_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static int ocf_metadata_load_atomic_metadata_drain(void *priv,
		uint64_t sector_addr, uint32_t sector_no, ctx_data_t *data)
{
	struct ocf_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;
	struct ocf_atomic_metadata meta;
	ocf_cache_line_t line = 0;
	uint8_t pos = 0;
	ocf_seq_no_t core_seq_no = OCF_SEQ_NO_INVALID;
	ocf_core_id_t core_id = OCF_CORE_ID_INVALID;
	uint64_t core_line = 0;
	bool core_line_ok = false;
	uint32_t i;

	for (i = 0; i < sector_no; i++) {
		ctx_data_rd_check(cache->owner, &meta, data, sizeof(meta));

		line = (sector_addr + i) / ocf_line_blocks(cache);
		pos = (sector_addr + i) % ocf_line_blocks(cache);
		core_seq_no = meta.core_seq_no;
		core_line = meta.core_line;

		/* Look for core with sequence number same as cache line */
		core_id = _ocf_metadata_find_core_by_seq(
				cache, core_seq_no);

		if (pos == 0)
			core_line_ok = false;

		if (meta.valid && core_id != OCF_CORE_ID_INVALID) {
			if (!core_line_ok) {
				ocf_metadata_set_core_info(cache, line,
							core_id, core_line);
				core_line_ok = true;
			}

			metadata_set_valid_sec_one(cache, line, pos);
			meta.dirty ?
				metadata_set_dirty_sec_one(cache, line, pos) :
				metadata_clear_dirty_sec_one(cache, line, pos);
		}
	}

	return 0;
}

static void ocf_metadata_load_atomic_metadata(
		ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	result = metadata_io_read_i_atomic(cache, cache->mngt_queue,
			context, ocf_metadata_load_atomic_metadata_drain,
			ocf_metadata_load_atomic_metadata_complete);
	if (result) {
		ocf_metadata_error(cache);
		ocf_cache_log(cache, log_err,
				"Metadata read for recovery FAILURE\n");
		OCF_PL_FINISH_RET(pipeline, result);
	}
}

static void ocf_metadata_load_recovery_atomic_finish(
		ocf_pipeline_t pipeline, void *priv, int error)
{
	struct ocf_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"Metadata read for recovery FAILURE\n");
		ocf_metadata_error(cache);
	}

	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_properties
ocf_metadata_load_recovery_atomic_pl_props = {
	.priv_size = sizeof(struct ocf_metadata_context),
	.finish = ocf_metadata_load_recovery_atomic_finish,
	.steps = {
		OCF_PL_STEP(ocf_metadata_load_atomic_metadata),
		OCF_PL_STEP_TERMINATOR(),
	},
};

/*
 * RAM Implementation - Load all metadata elements from SSD
 */
static void _ocf_metadata_load_recovery_atomic(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_DEBUG_TRACE(cache);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_metadata_load_recovery_atomic_pl_props);
	if (result)
		OCF_CMPL_RET(priv, result);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->ctrl = cache->metadata.priv;

	ocf_pipeline_next(pipeline);
}

/*
 * Load for recovery - Load only data that is required for recovery procedure
 */
void ocf_metadata_load_recovery(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	OCF_DEBUG_TRACE(cache);

	if (ocf_volume_is_atomic(&cache->device->volume))
		_ocf_metadata_load_recovery_atomic(cache, cmpl, priv);
	else
		_ocf_metadata_load_recovery_legacy(cache, cmpl, priv);
}

/*******************************************************************************
 * Core and part id
 ******************************************************************************/

void ocf_metadata_get_core_and_part_id(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_core_id_t *core_id,
		ocf_part_id_t *part_id)
{
	const struct ocf_metadata_map *collision;
	const struct ocf_lru_meta *info;

	collision = ocf_metadata_get_collision(cache, line);
	info = ocf_metadata_get_lru(cache, line);

	ENV_BUG_ON(!collision || !info);

	if (core_id)
		*core_id = collision->core_id;
	if (part_id)
		*part_id = info->partition_id;
}
/*******************************************************************************
 * Hash Table
 ******************************************************************************/

/*
 * Hash Table - Get
 */
struct ocf_hash_entry *ocf_metadata_get_hash_ptr(struct ocf_cache *cache,
		ocf_cache_line_t index)
{
	struct ocf_metadata_ctrl *ctrl
		= (struct ocf_metadata_ctrl *) cache->metadata.priv;

	return (struct ocf_hash_entry *)ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_hash]), index);
}

ocf_cache_line_t ocf_metadata_get_hash(struct ocf_cache *cache,
		ocf_cache_line_t index)
{
	struct ocf_hash_entry *entry = ocf_metadata_get_hash_ptr(cache, index);

	return entry->line;
}

/*
 * Hash Table - Set
 */
void ocf_metadata_set_hash(struct ocf_cache *cache, ocf_cache_line_t index,
		ocf_cache_line_t line)
{
	struct ocf_hash_entry *entry = ocf_metadata_get_hash_ptr(cache, index);

	ENV_BUG_ON(line > cache->device->collision_table_entries);

	entry->line = line;
}

/*******************************************************************************
 *  Bitmap status
 ******************************************************************************/

#define _ocf_metadata_funcs_5arg(what) \
bool ocf_metadata_##what(struct ocf_cache *cache, \
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all) \
{ \
	return ocf_metadata_bit_##what(ocf_metadata_get_collision(cache, line), \
			cache->metadata.line_size, start, stop, all); \
}

#define _ocf_metadata_funcs_4arg(what) \
bool ocf_metadata_##what(struct ocf_cache *cache, \
		ocf_cache_line_t line, uint8_t start, uint8_t stop) \
{ \
	return ocf_metadata_bit_##what(ocf_metadata_get_collision(cache, line), \
			cache->metadata.line_size, start, stop); \
}

#define _ocf_metadata_funcs(what) \
	_ocf_metadata_funcs_5arg(test_##what) \
	_ocf_metadata_funcs_4arg(test_out_##what) \
	_ocf_metadata_funcs_4arg(clear_##what) \
	_ocf_metadata_funcs_4arg(set_##what) \
	_ocf_metadata_funcs_5arg(test_and_set_##what) \
	_ocf_metadata_funcs_5arg(test_and_clear_##what)

_ocf_metadata_funcs(dirty)
_ocf_metadata_funcs(valid)

_ocf_metadata_funcs_4arg(clear_valid_if_clean)

void ocf_metadata_clear_dirty_if_invalid(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	ocf_metadata_bit_clear_dirty_if_invalid(
			ocf_metadata_get_collision(cache, line),
			cache->metadata.line_size, start, stop);
}

bool ocf_metadata_check(struct ocf_cache *cache, ocf_cache_line_t line)
{
	return ocf_metadata_bit_check(ocf_metadata_get_collision(cache, line),
			cache->metadata.line_size);
}

int ocf_metadata_init(struct ocf_cache *cache,
		ocf_cache_line_size_t cache_line_size)
{
	int ret;

	OCF_DEBUG_TRACE(cache);

	ret = ocf_metadata_init_fixed_size(cache, cache_line_size);
	if (ret)
		return ret;

	ret = ocf_metadata_concurrency_init(&cache->metadata.lock);
	if (ret) {
		ocf_metadata_deinit_fixed_size(cache);
		return ret;
	}

	return 0;
}

void ocf_metadata_deinit(struct ocf_cache *cache)
{
	OCF_DEBUG_TRACE(cache);

	ocf_metadata_deinit_fixed_size(cache);
	ocf_metadata_concurrency_deinit(&cache->metadata.lock);
}

void ocf_metadata_error(struct ocf_cache *cache)
{
	if (cache->device->metadata_error == 0)
		ocf_cache_log(cache, log_err, "Metadata Error\n");

	env_bit_clear(ocf_cache_state_running, &cache->cache_state);
	cache->device->metadata_error = -1;
}

struct ocf_metadata_load_properties_ctx
{
	ocf_cache_t cache;
	ocf_metadata_load_properties_end_t cmpl;
	void *priv;
};

static void ocf_metadata_load_properties_cmpl(
		struct ocf_metadata_read_sb_ctx *context)
{
	struct ocf_metadata_load_properties properties;
	struct ocf_superblock_config *superblock = &context->superblock;
	ocf_metadata_load_properties_end_t cmpl = context->priv1;
	void *priv = context->priv2;
	ocf_ctx_t ctx = context->ctx;
	int result;

	if (context->error)
		OCF_CMPL_RET(priv, context->error, NULL);

	result = ocf_metadata_validate_superblock(ctx, superblock);
	if (result)
		OCF_CMPL_RET(priv, result, NULL);

	properties.line_size = superblock->line_size;
	properties.cache_mode = superblock->cache_mode;
	properties.shutdown_status = superblock->clean_shutdown;
	properties.dirty_flushed = superblock->dirty_flushed;
	properties.cache_name = superblock->name;
	properties.cleaner_disabled = superblock->cleaner_disabled;

	OCF_CMPL_RET(priv, 0, &properties);
}

void ocf_metadata_load_properties(ocf_volume_t volume,
		ocf_metadata_load_properties_end_t cmpl, void *priv)
{
	int result;

	OCF_DEBUG_TRACE(volume->cache);

	result = ocf_metadata_read_sb(volume->cache->owner, volume,
			ocf_metadata_load_properties_cmpl, cmpl, priv);
	if (result)
		OCF_CMPL_RET(priv, result, NULL);
}

void ocf_metadata_zero_superblock(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *context)
{
	struct ocf_metadata_ctrl *ctrl = (struct ocf_metadata_ctrl *)
			cache->metadata.priv;

	ocf_metadata_sb_zero(ctrl->segment[metadata_segment_sb_config],
			cmpl, context);
}

static void ocf_metadata_probe_cmpl(struct ocf_metadata_read_sb_ctx *context)
{
	struct ocf_metadata_probe_status status;
	struct ocf_superblock_config *superblock = &context->superblock;
	ocf_metadata_probe_end_t cmpl = context->priv1;
	void *priv = context->priv2;

	if (context->error)
		OCF_CMPL_RET(priv, context->error, NULL);

	if (superblock->magic_number != CACHE_MAGIC_NUMBER)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_METADATA, NULL);

	if (superblock->clean_shutdown > ocf_metadata_clean_shutdown)
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL, NULL);

	if (superblock->dirty_flushed > DIRTY_FLUSHED)
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL, NULL);

	status.clean_shutdown = (superblock->clean_shutdown !=
			ocf_metadata_dirty_shutdown);
	status.cache_dirty = (superblock->dirty_flushed == DIRTY_NOT_FLUSHED);

	if (METADATA_VERSION() != superblock->metadata_version)
		OCF_CMPL_RET(priv, -OCF_ERR_METADATA_VER, &status);

	/*
	 * Following fields presence and offset is dependent on metadata
	 * version, so they can be safely accessed only after positive
	 * metadata version verification.
	 */

	if (env_strncmp(superblock->adapter_name, OCF_ADAPTER_NAME_SIZE,
			ENV_ADAPTER_NAME, OCF_ADAPTER_NAME_SIZE)) {
		OCF_CMPL_RET(priv, -OCF_ERR_ADAPTER_MISMATCH, &status);
	}

	if (superblock->adapter_version != ADAPTER_VERSION())
		OCF_CMPL_RET(priv, -OCF_ERR_ADAPTER_VER, &status);

	env_strncpy(status.cache_name, OCF_CACHE_NAME_SIZE, superblock->name,
			OCF_CACHE_NAME_SIZE);

	status.cache_mode = superblock->cache_mode;
	status.cache_line_size = superblock->line_size;

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

/*
 * Fast lookup to see if the line is a hit without bash bucket lock.
 */
bool ocf_metadata_is_hit_no_lock(ocf_cache_t cache, ocf_core_id_t core_id,
		uint64_t core_line)
{
	ocf_cache_line_t hash = ocf_metadata_hash_func(cache,
			core_line, core_id);
	ocf_cache_line_t line = ocf_metadata_get_hash(cache, hash);

	while (line != cache->device->collision_table_entries) {
		ocf_core_id_t curr_core_id;
		uint64_t curr_core_line;

		ocf_metadata_get_core_info(cache, line,
				&curr_core_id, &curr_core_line);

		if (curr_core_line == core_line && core_id == curr_core_id)
			return true;

		line = ocf_metadata_get_collision_next(cache, line);
	}

	return false;
}

