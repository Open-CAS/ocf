/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_env.h"
#include "ocf_env_refcnt.h"
#include "ocf_mngt_common.h"
#include "ocf_mngt_core_priv.h"
#include "../ocf_priv.h"
#include "../ocf_core_priv.h"
#include "../ocf_part.h"
#include "../ocf_queue_priv.h"
#include "../metadata/metadata.h"
#include "../metadata/metadata_io.h"
#include "../engine/cache_engine.h"
#include "../utils/utils_user_part.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_io.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_parallelize.h"
#include "../utils/utils_pipeline.h"
#include "../utils/utils_async_lock.h"
#include "../utils/utils_cleaner.h"
#include "../concurrency/ocf_concurrency.h"
#include "../concurrency/ocf_metadata_concurrency.h"
#include "../ocf_lru.h"
#include "../ocf_ctx_priv.h"
#include "../cleaning/cleaning.h"
#include "../promotion/ops.h"
#include "../concurrency/ocf_pio_concurrency.h"

#define OCF_ASSERT_PLUGGED(cache) ENV_BUG_ON(!(cache)->device)

#define DIRTY_SHUTDOWN_ERROR_MSG "Please use --load option to restore " \
	"previous cache state (Warning: data corruption may happen)"  \
	"\nOr initialize your cache using --force option. " \
	"Warning: All dirty data will be lost!\n"

#define DIRTY_NOT_FLUSHED_ERROR_MSG "Cache closed w/ no data flushing\n" \
	"Restart with --load or --force option\n"

/**
 * @brief Helpful struct to start cache
 */
struct ocf_cache_mngt_init_params {
	ocf_ctx_t ctx;
		/*!< OCF context */

	ocf_cache_t cache;
		/*!< cache that is being initialized */

	uint8_t locked;
		/*!< Keep cache locked */

	bool metadata_volatile;

	/**
	 * @brief initialization state (in case of error, it is used to know
	 * which assets have to be deallocated in premature exit from function
	 */
	struct {
		bool cache_alloc : 1;
			/*!< cache is allocated and added to list */

		bool metadata_inited : 1;
			/*!< Metadata is inited to valid state */

		bool cache_locked : 1;
			/*!< Cache has been locked */
	} flags;

	struct ocf_metadata_init_params {
		ocf_cache_line_size_t line_size;
		/*!< Metadata cache line size */

		ocf_cache_mode_t cache_mode;
		/*!< cache mode */

		ocf_promotion_t promotion_policy;
	} metadata;
};

typedef void (*_ocf_mngt_cache_attach_end_t)(ocf_cache_t, void *priv1,
	void *priv2, int error);

struct ocf_cache_attach_context {
	struct ocf_mngt_cache_attach_config cfg;

	ocf_cache_t cache;
		/*!< cache that is being initialized */


	uint64_t volume_size;
		/*!< size of the device in cache lines */

	struct ocf_volume cache_volume;

	/**
	 * @brief initialization state (in case of error, it is used to know
	 * which assets have to be deallocated in premature exit from function
	 */
	struct {
		bool device_alloc : 1;
			/*!< data structure allocated */

		bool volume_inited : 1;
			/*!< underlying device volume is initialized */

		bool volume_opened : 1;
			/*!< underlying device volume is open */

		bool front_volume_inited : 1;
			/*!< front volume is initialized */

		bool front_volume_opened : 1;
			/*!< front volume is open */

		bool attached_metadata_inited : 1;
			/*!< attached metadata sections initialized */

		bool cleaner_started : 1;
			/*!< Cleaner has been started */

		bool promotion_initialized : 1;
			/*!< Promotion policy has been started */

		bool cleaning_initialized : 1;
			/*!< Cleaning policy has been initialized */

		bool cores_opened : 1;
			/*!< underlying cores are opened (happens only during
			 * load or recovery
			 */

		bool metadata_frozen : 1;
			/*!< metadata reference counter frozen
			 */

		bool concurrency_inited : 1;

		bool pio_mpool : 1;

		bool pio_concurrency : 1;
	} flags;

	struct {
		ocf_cache_line_size_t line_size;
		/*!< Metadata cache line size */

		ocf_cache_mode_t cache_mode;
		/*!< cache mode */

		enum ocf_metadata_shutdown_status shutdown_status;
		/*!< dirty or clean */

		uint8_t dirty_flushed;
		/*!< is dirty data fully flushed */

		bool cleaner_disabled;
		/*!< is cleaner disabled */
	} metadata;

	struct {
		void *rw_buffer;
		void *cmp_buffer;
		unsigned long reserved_lba_addr;
		ocf_pipeline_t pipeline;
	} test;

	_ocf_mngt_cache_attach_end_t cmpl;
	void *priv1;
	void *priv2;

	ocf_pipeline_t pipeline;
};

static void _ocf_mngt_cache_set_detached(ocf_cache_t cache);

static void __init_partitions(ocf_cache_t cache)
{
	ocf_part_id_t i_part;

	/* Init default Partition */
	ENV_BUG_ON(ocf_mngt_add_partition_to_cache(cache, PARTITION_DEFAULT,
			"unclassified", 0, PARTITION_SIZE_MAX,
			OCF_IO_CLASS_PRIO_LOWEST, true));

	/* Add other partition to the cache and make it as dummy */
	for (i_part = 0; i_part < OCF_USER_IO_CLASS_MAX; i_part++) {
		env_refcnt_freeze(&cache->user_parts[i_part].cleaning.counter);

		if (i_part == PARTITION_DEFAULT)
			continue;

		/* Init default Partition */
		ENV_BUG_ON(ocf_mngt_add_partition_to_cache(cache, i_part,
				"Inactive", 0, PARTITION_SIZE_MAX,
				OCF_IO_CLASS_PRIO_LOWEST, false));
	}
}

static void _init_parts_attached(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_init_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_part_id_t part_id;

	for (part_id = 0; part_id < OCF_USER_IO_CLASS_MAX; part_id++)
		ocf_lru_init(cache, &cache->user_parts[part_id].part);

	ocf_lru_init(cache, &cache->free);
	ocf_lru_init(cache, &cache->free_detached);

	ocf_pipeline_next(pipeline);
}

static ocf_error_t __init_cleaning_policy(ocf_cache_t cache)
{
	int result;
	int i;

	OCF_ASSERT_PLUGGED(cache);

	result = env_refcnt_init(&cache->cleaner.refcnt, "cleaner",
			sizeof("cleaner"));
	if (result)
		return result;

	for (i = 0; i < ocf_cleaning_max; i++)
		ocf_cleaning_setup(cache, i);

	result = ocf_cleaning_initialize(cache, cache->cleaner.policy);
	if (result)
		env_refcnt_deinit(&cache->cleaner.refcnt);

	return result;
}

static void __deinit_cleaning_policy(ocf_cache_t cache)
{
	ocf_cleaning_deinitialize(cache);
	env_refcnt_deinit(&cache->cleaner.refcnt);
}

static void __setup_promotion_policy(ocf_cache_t cache)
{
	int i;

	OCF_CHECK_NULL(cache);

	for (i = 0; i < ocf_promotion_max; i++) {
		if (ocf_promotion_policies[i].setup)
			ocf_promotion_policies[i].setup(cache);
	}
}

static void __deinit_promotion_policy(ocf_cache_t cache)
{
	if (cache->promotion_policy) {
		ocf_promotion_deinit(cache->promotion_policy);
		cache->promotion_policy = NULL;
	}
}

static void __init_free(ocf_cache_t cache)
{
	cache->free.id = PARTITION_FREELIST;
	cache->free_detached.id = PARTITION_FREELIST;
}

static void __init_cores(ocf_cache_t cache)
{
	/* No core devices yet */
	cache->conf_meta->core_count = 0;
	ENV_BUG_ON(env_memset(cache->conf_meta->valid_core_bitmap,
			sizeof(cache->conf_meta->valid_core_bitmap), 0));
}

static void __init_metadata_version(ocf_cache_t cache)
{
	cache->conf_meta->metadata_version = METADATA_VERSION();
}

static void _reset_stats(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_init_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core;
	ocf_core_id_t core_id;
	ocf_part_id_t i;

	for_each_core_all(cache, core, core_id) {
		env_atomic_set(&core->runtime_meta->cached_clines, 0);
		env_atomic_set(&core->runtime_meta->dirty_clines, 0);
		env_atomic64_set(&core->runtime_meta->dirty_since, 0);

		for (i = 0; i != OCF_USER_IO_CLASS_MAX; i++) {
			env_atomic_set(&core->runtime_meta->
					part_counters[i].cached_clines, 0);
			env_atomic_set(&core->runtime_meta->
					part_counters[i].dirty_clines, 0);
		}
	}

	ocf_pipeline_next(pipeline);
}

static void _init_metadata_version(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_init_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;

	__init_metadata_version(cache);

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_init_metadata_finish(ocf_pipeline_t pipeline,
			void *priv, int error)
{
	struct ocf_init_metadata_context *context = priv;

	context->cmpl(context->priv, error);

	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_properties ocf_init_attached_recovery_props = {
	.priv_size = sizeof(struct ocf_init_metadata_context),
	.finish = _ocf_mngt_init_metadata_finish,
	.steps = {
		OCF_PL_STEP(ocf_metadata_init_hash_table),
		OCF_PL_STEP(ocf_metadata_init_collision),
		OCF_PL_STEP(_init_parts_attached),
		OCF_PL_STEP(_reset_stats),
		OCF_PL_STEP(_init_metadata_version),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void init_attached_data_structures_recovery(ocf_cache_t cache,
		ocf_mngt_init_metadata_end_t cmpl, void *priv, bool skip_collision)
{
	struct ocf_init_metadata_context *context;
	ocf_pipeline_t pipeline;
	int result;

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_init_attached_recovery_props);
	if (result)
		OCF_CMPL_RET(priv, result);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->skip_collision = skip_collision;

	OCF_PL_NEXT_RET(pipeline);
}

/****************************************************************
 * Function for removing all initialized core objects		*
 * from the cache instance.					*
 * Used in case of cache initialization errors.			*
 ****************************************************************/
static void _ocf_mngt_deinit_added_cores(
		struct ocf_cache_attach_context *context)
{
	ocf_cache_t cache = context->cache;
	ocf_core_t core;
	ocf_core_id_t core_id;
	ocf_volume_t volume;

	for_each_core(cache, core, core_id) {
		volume = &core->volume;
		if (context->cfg.open_cores)
			ocf_volume_close(volume);

		if (core->front_volume.opened) {
			ocf_volume_close(&core->front_volume);
			ocf_volume_deinit(&core->front_volume);
		}

		if (core->seq_cutoff)
			ocf_core_seq_cutoff_deinit(core);

		env_free(core->counters);
		core->counters = NULL;
		core->added = false;
	}
}

/**
 * @brief routine loading metadata from cache device
 *  - attempts to open all the underlying cores
 */
static void _ocf_mngt_load_add_cores(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core;
	ocf_core_id_t core_id;
	int ret = -1;
	uint64_t hd_lines = 0;
	uint64_t length;
	ocf_error_t error = -OCF_ERR_START_CACHE_FAIL;

	OCF_ASSERT_PLUGGED(cache);

	/* Check in metadata which cores were saved in cache metadata */
	for_each_core_metadata(cache, core, core_id) {
		struct ocf_metadata_uuid *muuid;
		struct ocf_volume_uuid uuid;
		ocf_volume_type_t volume_type;
		ocf_volume_t tvolume = NULL;

		muuid = ocf_metadata_get_core_uuid(cache, core_id);
		uuid.data = muuid->data;
		uuid.size = muuid->size;

		volume_type = ocf_ctx_get_volume_type(cache->owner,
				core->conf_meta->type);

		ret = ocf_volume_init(&core->volume, volume_type, &uuid, false);
		if (ret)
			goto err;
		core->has_volume = true;

		tvolume = ocf_mngt_core_pool_lookup(ocf_cache_get_ctx(cache),
				&core->volume.uuid, core->volume.type);
		if (tvolume) {
			/*
			 * Attach bottom device to core structure
			 * in cache
			 */
			env_refcnt_freeze(&tvolume->refcnt);
			ocf_volume_move(&core->volume, tvolume);
			env_refcnt_unfreeze(&tvolume->refcnt);
			ocf_mngt_core_pool_remove(cache->owner, tvolume);

			core->opened = true;
			ocf_cache_log(cache, log_info,
					"Attached core %u from pool\n",
					core_id);
		} else if (context->cfg.open_cores) {
			ret = ocf_volume_open(&core->volume, NULL);
			if (ret == -OCF_ERR_NOT_OPEN_EXC) {
				ocf_cache_log(cache, log_warn,
						"Cannot open core %u. "
						"Cache is busy", core_id);
			} else if (ret) {
				ocf_cache_log(cache, log_warn,
						"Cannot open core %u", core_id);
			} else {
				core->opened = true;
			}

		}
		core->added = true;
		core->volume.cache = cache;

		if (ocf_mngt_core_init_front_volume(core))
			goto err;

		core->counters =
			env_zalloc(sizeof(*core->counters), ENV_MEM_NORMAL);
		if (!core->counters)
			goto err;

		ret = ocf_core_seq_cutoff_init(core);
		if (ret < 0)
			goto err;

		if (!core->opened) {
			env_bit_set(ocf_cache_state_incomplete,
					&cache->cache_state);
			cache->ocf_core_inactive_count++;
			ocf_cache_log(cache, log_warn,
					"Cannot find core %u in pool"
					", core added as inactive\n", core_id);
			continue;
		}

		length = ocf_volume_get_length(&core->volume);
		if (length != core->conf_meta->length) {
			ocf_core_log(core, log_err,
					"Size of core volume doesn't match with"
					" the size stored in cache metadata!");
			error = -OCF_ERR_CORE_SIZE_MISMATCH;
			goto err;
		}

		hd_lines = ocf_bytes_2_lines(cache, length);

		if (hd_lines) {
			ocf_cache_log(cache, log_info,
				"Disk lines = %" ENV_PRIu64 "\n", hd_lines);
		}
	}

	context->flags.cores_opened = true;
	OCF_PL_NEXT_RET(context->pipeline);

err:
	_ocf_mngt_deinit_added_cores(context);

	OCF_PL_FINISH_RET(pipeline, error);
}

typedef void (*ocf_mngt_rebuild_metadata_end_t)(void *priv, int error);

/*
 * IMPORTANT: This value must match number of LRU lists so that adding
 * cache lines to the list can be implemented without locking (each shard
 * owns it's own LRU list). Don't change this value unless you are really
 * sure you know what you're doing.
 */
#define OCF_MNGT_REBUILD_METADATA_SHARDS_CNT OCF_NUM_LRU_LISTS

struct ocf_mngt_rebuild_metadata_context {
	ocf_cache_t cache;

	struct {
		env_atomic lines;
	} core[OCF_CORE_MAX];

	struct {
		struct {
			uint32_t lines;
		} core[OCF_CORE_MAX];
	} shard[OCF_MNGT_REBUILD_METADATA_SHARDS_CNT];

	env_atomic free_lines;

	ocf_mngt_rebuild_metadata_end_t cmpl;
	void *priv;
};

static void ocf_mngt_cline_reset_metadata(ocf_cache_t cache,
		ocf_cache_line_t cline, uint32_t lru_list)
{
	ocf_metadata_set_core_info(cache, cline, OCF_CORE_MAX, ULLONG_MAX);
	metadata_init_status_bits(cache, cline);

	ocf_metadata_set_partition_id(cache, cline, PARTITION_FREELIST);

	ocf_lru_add_free(cache, cline);
}

static void ocf_mngt_cline_rebuild_metadata(ocf_cache_t cache,
		ocf_core_id_t core_id, uint64_t core_line,
		ocf_cache_line_t cline)
{
	ocf_part_id_t part_id = PARTITION_DEFAULT;
	ocf_cache_line_t hash_index;

	ocf_metadata_set_partition_id(cache, cline, part_id);

	hash_index = ocf_metadata_hash_func(cache, core_line, core_id);

	ocf_hb_id_naked_lock_wr(&cache->metadata.lock, hash_index);
	ocf_metadata_add_to_collision(cache, core_id, core_line, hash_index,
			cline);
	ocf_hb_id_naked_unlock_wr(&cache->metadata.lock, hash_index);

	ocf_lru_init_cline(cache, cline);

	ocf_lru_add(cache, cline);
}

static int ocf_mngt_rebuild_metadata_handle(ocf_parallelize_t parallelize,
		void *priv, unsigned shard_id, unsigned shards_cnt)
{
	struct ocf_mngt_rebuild_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_cache_line_t begin, increment, cline, free_lines;
	ocf_core_t core;
	ocf_core_id_t core_id;
	uint64_t core_line;
	unsigned char step = 0;
	const uint64_t entries = ocf_metadata_collision_table_entries(cache);

	begin = shard_id;
	increment = shards_cnt;

	free_lines = 0;
	for (cline = begin; cline < entries; cline += increment) {
		bool any_valid = true;

		OCF_COND_RESCHED(step, 128);
		ocf_metadata_get_core_info(cache, cline, &core_id, &core_line);

		if (!ocf_metadata_check(cache, cline) ||
				core_id > OCF_CORE_MAX) {
			ocf_cache_log(cache, log_err, "Inconsistent mapping "
					"detected in on-disk metadata - "
					"refusing to recover cache.\n");
			return -OCF_ERR_INVAL;
		}

		any_valid = metadata_clear_valid_if_clean(cache, cline);
		if (!any_valid || core_id == OCF_CORE_MAX) {
			/* Reset metadata for not mapped or clean cache line */
			ocf_mngt_cline_reset_metadata(cache, cline, shard_id);
			free_lines++;
			continue;
		}

		if (!cache->core[core_id].conf_meta->valid) {
			ocf_cache_log(cache, log_err, "Stale mapping in "
					"on-disk metadata - refusing to "
					"recover cache.\n");
			return -OCF_ERR_INVAL;
		}

		/* Rebuild metadata for mapped cache line */
		ocf_mngt_cline_rebuild_metadata(cache, core_id,
				core_line, cline);

		context->shard[shard_id].core[core_id].lines++;
	}

	for_each_core(cache, core, core_id) {
		env_atomic_add(context->shard[shard_id].core[core_id].lines,
				&context->core[core_id].lines);
	}

	env_atomic_add(free_lines, &context->free_lines);

	return 0;
}

static void ocf_mngt_rebuild_metadata_finish(ocf_parallelize_t parallelize,
		void *priv, int error)
{
	struct ocf_mngt_rebuild_metadata_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_part_id_t part_id = PARTITION_DEFAULT;
	struct ocf_part_runtime *part;
	ocf_core_t core;
	ocf_core_id_t core_id;
	uint32_t lines_total = 0;

	for_each_core(cache, core, core_id) {
		uint32_t lines = env_atomic_read(&context->core[core_id].lines);

		env_atomic_set(&core->runtime_meta->cached_clines, lines);
		env_atomic_set(&core->runtime_meta->
				part_counters[part_id].cached_clines, lines);
		env_atomic_set(&core->runtime_meta->dirty_clines, lines);
		env_atomic_set(&core->runtime_meta->
				part_counters[part_id].dirty_clines, lines);
		if (lines) {
			env_atomic64_set(&core->runtime_meta->dirty_since,
					env_ticks_to_secs(env_get_tick_count()));
		}

		lines_total += lines;
	}

	part = cache->user_parts[part_id].part.runtime;
	env_atomic_set(&part->curr_size, lines_total);

	env_atomic_set(&cache->free.runtime->curr_size,
			env_atomic_read(&context->free_lines));

	context->cmpl(context->priv, error);

	ocf_parallelize_destroy(parallelize);
}

static void ocf_mngt_rebuild_metadata(ocf_cache_t cache,
		ocf_mngt_rebuild_metadata_end_t cmpl, void *priv)
{
	struct ocf_mngt_rebuild_metadata_context *context;
	ocf_parallelize_t parallelize;
	int result;

	result = ocf_parallelize_create(&parallelize, cache,
			OCF_MNGT_REBUILD_METADATA_SHARDS_CNT,
			sizeof(*context), ocf_mngt_rebuild_metadata_handle,
			ocf_mngt_rebuild_metadata_finish, false);
        if (result) {
                cmpl(priv, result);
                return;
	}

	context = ocf_parallelize_get_priv(parallelize);
	context->cache = cache;
	context->cmpl = cmpl;
	context->priv = priv;

	ocf_parallelize_run(parallelize);
}

static void _ocf_mngt_load_rebuild_metadata_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static void _ocf_mngt_load_rebuild_metadata(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (context->metadata.shutdown_status != ocf_metadata_clean_shutdown) {
		ocf_mngt_rebuild_metadata(cache,
				_ocf_mngt_load_rebuild_metadata_complete,
				context);
		return;
	}

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_cleaning_populate_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static void _ocf_mngt_load_init_cleaning(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	bool reconstruct = context->metadata.shutdown_status ==
			ocf_metadata_dirty_shutdown;
	ocf_error_t result;

	result = env_refcnt_init(&cache->cleaner.refcnt, "cleaner", sizeof("cleaner"));
	if (result) {
		ocf_cache_log(cache, log_err, "Cannot initialize cleaner refcount\n");
		OCF_PL_FINISH_RET(pipeline, result);
	}

	result = ocf_cleaning_initialize(cache, cache->cleaner.policy);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);

	ocf_cleaning_populate(cache, cache->cleaner.policy, reconstruct,
			_ocf_mngt_cleaning_populate_complete, context);
}

static void _ocf_mngt_init_metadata_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cannot initialize cache metadata\n");
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_NO_MEM);
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_load_init_structures(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (context->metadata.shutdown_status == ocf_metadata_clean_shutdown)
		OCF_PL_NEXT_RET(pipeline);

	init_attached_data_structures_recovery(cache,
			_ocf_mngt_init_metadata_complete, context, false);
}

static void _ocf_mngt_load_metadata_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"Cannot read cache metadata\n");
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_START_CACHE_FAIL);
	}

	ocf_pipeline_next(context->pipeline);
}

/**
 * handle load variant
 */
static void _ocf_mngt_load_metadata_clean(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_metadata_load_all(cache,
			_ocf_mngt_load_metadata_complete, context);
}

/**
 * handle recovery variant
 */
static void _ocf_mngt_load_metadata_recovery(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_metadata_load_recovery(cache,
			_ocf_mngt_load_metadata_complete, context);
}

static void _ocf_mngt_load_metadata(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (context->metadata.shutdown_status == ocf_metadata_clean_shutdown) {
		_ocf_mngt_load_metadata_clean(pipeline, priv, arg);
	} else {
		ocf_cache_log(cache, log_warn,
			"ERROR: Cache device did not shut down properly!\n");
		ocf_cache_log(cache, log_info, "Initiating recovery sequence...\n");
		_ocf_mngt_load_metadata_recovery(pipeline, priv, arg);
	}
}

/**
 * @brief allocate memory for new cache, add it to cache queue, set initial
 * values and running state
 */
static int _ocf_mngt_init_new_cache(struct ocf_cache_mngt_init_params *params,
		char *new_cache_name)
{
	ocf_cache_t cache = env_vzalloc(sizeof(*cache));
	int result = 0;
	int i = 0;

	if (!cache) {
		ocf_log(params->ctx, log_err, "Failed to allocate cache %s\n",
				new_cache_name);
		return -OCF_ERR_NO_MEM;
	}

	if (ocf_mngt_cache_lock_init(cache)) {
		ocf_log(params->ctx, log_err,
				"Failed to allocate cache %s lock\n",
				new_cache_name);
		result = -OCF_ERR_NO_MEM;
		goto alloc_err;
	}

	result = env_refcnt_init(&cache->refcnt.cache, "cache", sizeof("cache"));
	if (result)
		goto lock_init_err;

	result = env_refcnt_init(&cache->refcnt.dirty, "dirty", sizeof("dirty"));
	if (result)
		goto dirty_refcnt_err;

	result = env_refcnt_init(&cache->refcnt.metadata, "metadata", sizeof("metadata"));
	if (result)
		goto metadata_refcnt_err;

	result = env_refcnt_init(&cache->refcnt.d2c, "d2c", sizeof("d2c"));
	if (result)
		goto d2c_refcnt_err;

        for (i = 0; i < OCF_USER_IO_CLASS_MAX; i++) {
		result = env_refcnt_init(&cache->user_parts[i].cleaning.counter,
			    "cleaning", sizeof("cleaning"));
		if (result)
			goto cleaning_refcnt_err;
		env_atomic_set(&cache->user_parts[i].cleaning.cleaner_running, 0);
	}

	/* Lock cache during setup - this trylock should always succeed */
	result = ocf_mngt_cache_trylock(cache);
	if (result) {
		ocf_log(params->ctx, log_crit,
				"Failed to lock the newly created cache %s\n",
				new_cache_name);
		goto cleaning_refcnt_err;
	}

	if (env_mutex_init(&cache->flush_mutex)) {
		ocf_log(params->ctx, log_err,
				"Failed to allocate cache %s flush lock\n",
				new_cache_name);
		result = -OCF_ERR_NO_MEM;
		goto lock_err;
	}

	INIT_LIST_HEAD(&cache->io_queues);
	result = env_spinlock_init(&cache->io_queues_lock);
	if (result) {
		ocf_log(params->ctx, log_err,
				"Failed to allocate cache %s queue lock\n",
				new_cache_name);
		goto mutex_err;
	}

	result = !env_refcnt_inc(&cache->refcnt.cache);
	if (result) {
		ocf_log(params->ctx, log_crit,
				"Failed to increment %s refcnt\n",
				new_cache_name);
		goto cache_refcnt_inc_err;
	}

	/* start with frozen metadata ref counter to indicate detached device*/
	env_refcnt_freeze(&cache->refcnt.metadata);

	env_atomic_set(&(cache->last_access_ms),
			env_ticks_to_msecs(env_get_tick_count()));

	_ocf_mngt_cache_set_detached(cache);

	params->cache = cache;
	params->flags.cache_alloc = true;

	return 0;

cache_refcnt_inc_err:
	env_spinlock_destroy(&cache->io_queues_lock);
mutex_err:
	env_mutex_destroy(&cache->flush_mutex);
lock_err:
	ocf_mngt_cache_unlock(cache);
cleaning_refcnt_err:
	for (; i >= 0; i--) {
		env_refcnt_deinit(&cache->user_parts[i].cleaning.counter);
	}
	env_refcnt_deinit(&cache->refcnt.d2c);
d2c_refcnt_err:
	env_refcnt_deinit(&cache->refcnt.metadata);
metadata_refcnt_err:
	env_refcnt_deinit(&cache->refcnt.dirty);
dirty_refcnt_err:
	env_refcnt_deinit(&cache->refcnt.cache);
lock_init_err:
	ocf_mngt_cache_lock_deinit(cache);
alloc_err:
	env_vfree(cache);

	return result;
}

static void _ocf_mngt_attach_cache_device(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	struct ocf_mngt_cache_device_config *device_cfg = &context->cfg.device;
	ocf_cache_t cache = context->cache;
	int ret;

	cache->device = env_vzalloc(sizeof(*cache->device));
	if (!cache->device)
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_NO_MEM);

	context->flags.device_alloc = true;

	ret = ocf_volume_init(&cache->device->volume, device_cfg->volume->type,
			NULL, false);
	if (ret)
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_NO_MEM);

	context->flags.volume_inited = true;

	ocf_volume_move(&cache->device->volume, device_cfg->volume);
	cache->device->volume.cache = cache;

	/*
	 * Open cache device, It has to be done first because metadata service
	 * need to know size of cache device.
	 */
	ret = ocf_volume_open(&cache->device->volume,
			device_cfg->volume_params);
	if (ret) {
		ocf_cache_log(cache, log_err, "ERROR: Cache not available\n");
		OCF_PL_FINISH_RET(pipeline, ret);
	}
	context->flags.volume_opened = true;

	context->volume_size = ocf_volume_get_length(&cache->device->volume);

	/* Check minimum size of cache device */
	if (context->volume_size < OCF_CACHE_SIZE_MIN) {
		ocf_cache_log(cache, log_err, "Cache device size must "
			"be at least %llu MiB\n", OCF_CACHE_SIZE_MIN / MiB);
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_INVAL_CACHE_DEV);
	}

	ocf_pipeline_next(pipeline);
}

/**
 * @brief prepare cache for init. This is first step towards initializing
 *		the cache
 */
static int _ocf_mngt_init_prepare_cache(struct ocf_cache_mngt_init_params *param,
		struct ocf_mngt_cache_config *cfg)
{
	ocf_cache_t cache;
	int ret = 0;

	/* Check if cache with specified name exists */
	ret = ocf_mngt_cache_get_by_name(param->ctx, cfg->name,
					OCF_CACHE_NAME_SIZE, &cache);
	if (!ret) {
		ocf_mngt_cache_put(cache);
		/* Cache already exist */
		ret = -OCF_ERR_CACHE_EXIST;
		goto out;
	}

	ocf_log(param->ctx, log_info, "Inserting cache %s\n", cfg->name);

	ret = _ocf_mngt_init_new_cache(param, cfg->name);
	if (ret)
		goto out;

	cache = param->cache;

	cache->backfill.max_queue_size = cfg->backfill.max_queue_size;
	cache->backfill.queue_unblock_size = cfg->backfill.queue_unblock_size;

	param->flags.cache_locked = true;

	cache->pt_unaligned_io = cfg->pt_unaligned_io;
	cache->use_submit_io_fast = cfg->use_submit_io_fast;

	cache->metadata.is_volatile = cfg->metadata_volatile;

out:
	return ret;
}

static void _ocf_mngt_test_volume_initial_write_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->test.pipeline, error);
}

static void _ocf_mngt_test_volume_initial_write(
		ocf_pipeline_t test_pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	/*
	 * Write buffer filled with "1"
	 */

	ENV_BUG_ON(env_memset(context->test.rw_buffer, PAGE_SIZE, 1));

	ocf_submit_cache_page(cache, context->test.reserved_lba_addr,
			OCF_WRITE, context->test.rw_buffer,
			_ocf_mngt_test_volume_initial_write_complete, context);
}

static void _ocf_mngt_test_volume_first_read_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int ret, diff;

	if (error)
		OCF_PL_FINISH_RET(context->test.pipeline, error);

	ret = env_memcmp(context->test.rw_buffer, PAGE_SIZE,
			context->test.cmp_buffer, PAGE_SIZE, &diff);
	if (ret)
		OCF_PL_FINISH_RET(context->test.pipeline, ret);

	if (diff) {
		/* we read back different data than what we had just
		   written - this is fatal error */
		OCF_PL_FINISH_RET(context->test.pipeline, -OCF_ERR_IO);
	}

	if (!ocf_volume_is_atomic(&cache->device->volume)) {
		/* If not atomic, stop testing here */
		OCF_PL_FINISH_RET(context->test.pipeline, 0);
	}

	ocf_pipeline_next(context->test.pipeline);
}

static void _ocf_mngt_test_volume_first_read(
		ocf_pipeline_t test_pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	/*
	 * First read
	 */

	ENV_BUG_ON(env_memset(context->test.rw_buffer, PAGE_SIZE, 0));
	ENV_BUG_ON(env_memset(context->test.cmp_buffer, PAGE_SIZE, 1));

	ocf_submit_cache_page(cache, context->test.reserved_lba_addr,
			OCF_READ, context->test.rw_buffer,
			_ocf_mngt_test_volume_first_read_complete, context);
}

static void _ocf_mngt_test_volume_discard_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->test.pipeline, error);
}

static void _ocf_mngt_test_volume_discard(
		ocf_pipeline_t test_pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	/*
	 * Submit discard request
	 */

	ocf_submit_cache_discard(cache, context->test.reserved_lba_addr,
			PAGE_SIZE, _ocf_mngt_test_volume_discard_complete,
			context);
}

static void _ocf_mngt_test_volume_second_read_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int ret, diff;

	if (error)
		OCF_PL_FINISH_RET(context->test.pipeline, error);

	ret = env_memcmp(context->test.rw_buffer, PAGE_SIZE,
			context->test.cmp_buffer, PAGE_SIZE, &diff);
	if (ret)
		OCF_PL_FINISH_RET(context->test.pipeline, ret);

	if (diff) {
		/* discard does not cause target adresses to return 0 on
		   subsequent read */
		cache->device->volume.features.discard_zeroes = 0;
	}

	ocf_pipeline_next(context->test.pipeline);
}

static void _ocf_mngt_test_volume_second_read(
		ocf_pipeline_t test_pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	/*
	 * Second read
	 */

	ENV_BUG_ON(env_memset(context->test.rw_buffer, PAGE_SIZE, 1));
	ENV_BUG_ON(env_memset(context->test.cmp_buffer, PAGE_SIZE, 0));

	ocf_submit_cache_page(cache, context->test.reserved_lba_addr,
			OCF_READ, context->test.rw_buffer,
			_ocf_mngt_test_volume_second_read_complete, context);
}

static void _ocf_mngt_test_volume_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	env_free(context->test.rw_buffer);
	env_free(context->test.cmp_buffer);

	ocf_pipeline_destroy(context->test.pipeline);

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

struct ocf_pipeline_properties _ocf_mngt_test_volume_pipeline_properties = {
	.priv_size = 0,
	.finish = _ocf_mngt_test_volume_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_test_volume_initial_write),
		OCF_PL_STEP(_ocf_mngt_test_volume_first_read),
		OCF_PL_STEP(_ocf_mngt_test_volume_discard),
		OCF_PL_STEP(_ocf_mngt_test_volume_second_read),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void _ocf_mngt_test_volume(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	struct ocf_mngt_cache_device_config *device_cfg = &context->cfg.device;
	ocf_cache_t cache = context->cache;
	ocf_pipeline_t test_pipeline;
	int result;

	cache->device->volume.features.discard_zeroes = 1;

	if (!device_cfg->perform_test)
		OCF_PL_NEXT_RET(pipeline);

	context->test.reserved_lba_addr = ocf_metadata_get_reserved_lba(cache);

	context->test.rw_buffer = env_malloc(PAGE_SIZE, ENV_MEM_NORMAL);
	if (!context->test.rw_buffer)
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_NO_MEM);

	context->test.cmp_buffer = env_malloc(PAGE_SIZE, ENV_MEM_NORMAL);
	if (!context->test.cmp_buffer)
		goto err_buffer;

	result = ocf_pipeline_create(&test_pipeline, cache,
			&_ocf_mngt_test_volume_pipeline_properties);
	if (result)
		goto err_pipeline;

	ocf_pipeline_set_priv(test_pipeline, context);

	context->test.pipeline = test_pipeline;

	OCF_PL_NEXT_RET(test_pipeline);

err_pipeline:
	env_free(context->test.rw_buffer);
err_buffer:
	env_free(context->test.cmp_buffer);
	OCF_PL_FINISH_RET(pipeline, -OCF_ERR_NO_MEM);
}

static void _ocf_mngt_attach_read_properties_end(void *priv, int error,
		struct ocf_metadata_load_properties *properties)
{
	struct ocf_cache_attach_context *context = priv;

	if (error != -OCF_ERR_NO_METADATA) {
		if (!error) {
			/*
			 * To prevent silent metadata overriding, return error if old
			 * metadata was detected when attempting to attach cache.
			 */
			OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_METADATA_FOUND);
		}
		OCF_PL_FINISH_RET(context->pipeline, error);
	}

	/* No metadata exists on the device */
	OCF_PL_NEXT_RET(context->pipeline);
}

static void _ocf_mngt_load_read_properties_end(void *priv, int error,
		struct ocf_metadata_load_properties *properties)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error)
		OCF_PL_FINISH_RET(context->pipeline, error);

	/*
	 * Check if name loaded from disk is the same as present one.
	 */
	if (env_strncmp(cache->name, OCF_CACHE_NAME_SIZE,
			properties->cache_name, OCF_CACHE_NAME_SIZE)) {
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_CACHE_NAME_MISMATCH);
	}

	context->metadata.shutdown_status = properties->shutdown_status;
	context->metadata.dirty_flushed = properties->dirty_flushed;
	context->metadata.line_size = properties->line_size;
	context->metadata.cleaner_disabled = properties->cleaner_disabled;
	cache->conf_meta->cache_mode = properties->cache_mode;

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_init_properties(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	OCF_ASSERT_PLUGGED(cache);

	context->metadata.shutdown_status = ocf_metadata_clean_shutdown;
	context->metadata.dirty_flushed = DIRTY_FLUSHED;
	context->metadata.line_size = context->cfg.cache_line_size ?:
			cache->metadata.line_size;
	context->metadata.cleaner_disabled = context->cfg.disable_cleaner;

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_attach_read_properties(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (context->cfg.force)
		OCF_PL_NEXT_RET(pipeline);

	ocf_metadata_load_properties(&cache->device->volume,
			_ocf_mngt_attach_read_properties_end, context);
}

static void _ocf_mngt_load_read_properties(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_metadata_load_properties(&cache->device->volume,
			_ocf_mngt_load_read_properties_end, context);
}

static void _ocf_mngt_attach_prepare_metadata(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int ret;

	/*
	 * Initialize variable size metadata segments
	 */
	ret = ocf_metadata_init_variable_size(cache, context->volume_size,
			context->metadata.line_size,
			context->metadata.cleaner_disabled);
	if (ret)
		OCF_PL_FINISH_RET(pipeline, ret);

	context->flags.attached_metadata_inited = true;

	ret = ocf_concurrency_init(cache);
	if (ret)
		OCF_PL_FINISH_RET(pipeline, ret);

	context->flags.concurrency_inited = 1;

	ocf_pipeline_next(pipeline);
}

struct ocf_pipeline_properties ocf_init_metadata_pipeline_props = {
	.priv_size = sizeof(struct ocf_init_metadata_context),
	.finish = _ocf_mngt_init_metadata_finish,
	.steps = {
		OCF_PL_STEP(ocf_metadata_init_hash_table),
		OCF_PL_STEP(ocf_metadata_init_collision),
		OCF_PL_STEP(_init_parts_attached),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void _ocf_mngt_init_metadata(ocf_cache_t cache,
		ocf_mngt_init_metadata_end_t cmpl, void *priv)
{
	struct ocf_init_metadata_context *context;
	ocf_pipeline_t pipeline;
	int result;

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_init_metadata_pipeline_props);
	if (result)
		OCF_CMPL_RET(priv, result);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	OCF_PL_NEXT_RET(pipeline);
}

/**
 * @brief initializing cache anew (not loading or recovering)
 */
static void _ocf_mngt_attach_init_metadata(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	_ocf_mngt_init_metadata(cache, _ocf_mngt_init_metadata_complete,
			context);
}

static void _ocf_mngt_attach_populate_free_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static void _ocf_mngt_attach_populate_free(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_lru_populate(cache, _ocf_mngt_attach_populate_free_complete,
			context);
}

static void _ocf_mngt_cleaning_populate_init_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		env_refcnt_deinit(&cache->cleaner.refcnt);
		OCF_PL_FINISH_RET(context->pipeline, error);
	}

	/* In initial cache state there is no dirty data, so all dirty data is
	   considered to be flushed
	 */
	cache->conf_meta->dirty_flushed = true;

	context->flags.cleaning_initialized = true;

	OCF_PL_NEXT_RET(context->pipeline);
}

static void _ocf_mngt_attach_init_services(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_error_t result;

	__setup_promotion_policy(cache);

	if (context->metadata.cleaner_disabled)
		__set_cleaning_policy(cache, ocf_cleaning_nop);

	result = __init_cleaning_policy(cache);
	if (result) {
		ocf_cache_log(cache, log_err,
				"Cannot initialize cleaning policy\n");
		OCF_PL_FINISH_RET(pipeline, result);
	}

	ocf_cleaning_populate(cache, cache->cleaner.policy, true,
			_ocf_mngt_cleaning_populate_init_complete, context);
}

static uint64_t _ocf_mngt_calculate_ram_needed(ocf_cache_line_size_t line_size,
		uint64_t volume_size)
{
	uint64_t const_data_size;
	uint64_t cache_line_no;
	uint64_t data_per_line;
	uint64_t min_free_ram;

	/* Superblock + per core metadata */
	const_data_size = 100 * MiB;

	/* Cache metadata */
	cache_line_no = volume_size / line_size;
	data_per_line = (68 + (2 * (line_size / KiB / 4)));

	min_free_ram = const_data_size + cache_line_no * data_per_line;

	/* 110% of calculated value */
	min_free_ram = (11 * min_free_ram) / 10;

	return min_free_ram;
}

uint64_t ocf_mngt_get_ram_needed(ocf_cache_t cache,
		uint64_t volume_size)
{
	ocf_cache_line_size_t line_size;

	OCF_CHECK_NULL(cache);

	line_size = ocf_line_size(cache);

	return _ocf_mngt_calculate_ram_needed(line_size, volume_size);
}

/**
 * @brief for error handling do partial cleanup of datastructures upon
 * premature function exit.
 *
 * @param ctx OCF context
 * @param params - startup params containing initialization status flags.
 *
 */
static void _ocf_mngt_init_handle_error(ocf_ctx_t ctx,
		struct ocf_cache_mngt_init_params *params)
{
	int i;
	ocf_cache_t cache = params->cache;

	if (!params->flags.cache_alloc)
		return;

	env_spinlock_destroy(&cache->io_queues_lock);

	env_mutex_destroy(&cache->flush_mutex);

	if (params->flags.cache_locked)
		ocf_mngt_cache_unlock(cache);

	for (i = 0; i < OCF_USER_IO_CLASS_MAX; i++)
		env_refcnt_deinit(&cache->user_parts[i].cleaning.counter);

	env_refcnt_deinit(&cache->refcnt.d2c);
	env_refcnt_deinit(&cache->refcnt.metadata);
	env_refcnt_deinit(&cache->refcnt.dirty);
	env_refcnt_deinit(&cache->refcnt.cache);

	ocf_mngt_cache_lock_deinit(cache);

	if (params->flags.metadata_inited)
		ocf_metadata_deinit(cache);

	env_vfree(cache);
}

static void _ocf_mngt_cache_init(ocf_cache_t cache,
		struct ocf_cache_mngt_init_params *params)
{
	/*
	 * Super block elements initialization
	 */
	cache->conf_meta->cache_mode = params->metadata.cache_mode;
	cache->conf_meta->promotion_policy_type = params->metadata.promotion_policy;
	__set_cleaning_policy(cache, ocf_cleaning_default);

	/* Init Partitions */
	ocf_user_part_init(cache);
	__init_free(cache);

	__init_cores(cache);
	__init_metadata_version(cache);
	__init_partitions(cache);
}

static int _ocf_mngt_cache_start(ocf_ctx_t ctx, ocf_cache_t *cache,
		struct ocf_mngt_cache_config *cfg, void *priv)
{
	struct ocf_cache_mngt_init_params params;
	ocf_cache_t tmp_cache;
	int result;

	ENV_BUG_ON(env_memset(&params, sizeof(params), 0));

	params.ctx = ctx;
	params.metadata.cache_mode = cfg->cache_mode;
	params.metadata.line_size = cfg->cache_line_size;
	params.metadata_volatile = cfg->metadata_volatile;
	params.metadata.promotion_policy = cfg->promotion_policy;
	params.locked = cfg->locked;

	ocf_ctx_get(ctx);

	result = env_rmutex_lock_interruptible(&ctx->lock);
	if (result)
		goto _cache_mngt_init_instance_ERROR;

	/* Prepare cache */
	result = _ocf_mngt_init_prepare_cache(&params, cfg);
	if (result) {
		env_rmutex_unlock(&ctx->lock);
		ocf_log(ctx, log_err, "Failed to prepare cache %s\n",
				cfg->name);
		goto _cache_mngt_init_instance_ERROR;
	}

	tmp_cache = params.cache;
	tmp_cache->owner = ctx;
	tmp_cache->priv = priv;

	/*
	 * Initialize metadata selected segments of metadata in memory
	 */
	result = ocf_metadata_init(tmp_cache, params.metadata.line_size);
	if (result) {
		env_rmutex_unlock(&ctx->lock);
		ocf_log(ctx, log_err, "Failed to initialize cache %s "
				"metadata\n", cfg->name);
		result =  -OCF_ERR_NO_MEM;
		goto _cache_mngt_init_instance_ERROR;
	}
	params.flags.metadata_inited = true;

	result = ocf_cache_set_name(tmp_cache, cfg->name, OCF_CACHE_NAME_SIZE);
	if (result) {
		ocf_log(ctx, log_err, "Failed to set cache %s name\n",
				cfg->name);
		env_rmutex_unlock(&ctx->lock);
		goto _cache_mngt_init_instance_ERROR;
	}

	list_add_tail(&tmp_cache->list, &ctx->caches);
	env_rmutex_unlock(&ctx->lock);

	ocf_cache_log(tmp_cache, log_debug, "Metadata initialized\n");

	_ocf_mngt_cache_init(tmp_cache, &params);

	if (!params.locked) {
		/* User did not request to lock cache instance after creation -
		   unlock it here since we have acquired the lock to
		   perform management operations. */
		ocf_mngt_cache_unlock(tmp_cache);
		params.flags.cache_locked = false;
	}

	*cache = tmp_cache;

	return 0;

_cache_mngt_init_instance_ERROR:
	_ocf_mngt_init_handle_error(ctx, &params);
	*cache = NULL;
	ocf_ctx_put(ctx);
	return result;
}

static void _ocf_mngt_cache_set_valid(ocf_cache_t cache)
{
	/*
	 * Clear initialization state and set the valid bit so we know
	 * its in use.
	 */
	env_bit_clear(ocf_cache_state_detached, &cache->cache_state);
	env_bit_set(ocf_cache_state_running, &cache->cache_state);
}

static void _ocf_mngt_cache_set_standby(ocf_cache_t cache)
{
	/*
	 * Clear initialization state and set the standby bit.
	 */
	env_bit_clear(ocf_cache_state_detached, &cache->cache_state);
	env_bit_set(ocf_cache_state_standby, &cache->cache_state);
}

static void _ocf_mngt_cache_set_active(ocf_cache_t cache)
{
	/*
	 * Clear standby state and set the running bit.
	 */
	env_bit_clear(ocf_cache_state_standby, &cache->cache_state);
	env_bit_set(ocf_cache_state_running, &cache->cache_state);
}

static void _ocf_mngt_cache_set_detached(ocf_cache_t cache)
{
	env_bit_clear(ocf_cache_state_running, &cache->cache_state);
	env_bit_set(ocf_cache_state_detached, &cache->cache_state);
}

static void _ocf_mngt_init_attached_nonpersistent(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	env_atomic_set(&cache->fallback_pt_error_counter, 0);

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_attach_check_ram(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_cache_line_size_t line_size = context->metadata.line_size;
	uint64_t volume_size = ocf_volume_get_length(&cache->device->volume);
	uint64_t min_free_ram;
	uint64_t free_ram;

	min_free_ram = _ocf_mngt_calculate_ram_needed(line_size, volume_size);

	free_ram = env_get_free_memory();

	if (free_ram < min_free_ram) {
		ocf_cache_log(cache, log_err, "Not enough free RAM for cache "
				"metadata to start cache\n");
		ocf_cache_log(cache, log_err,
				"Available RAM: %" ENV_PRIu64 " B\n", free_ram);
		ocf_cache_log(cache, log_err, "Needed RAM: %" ENV_PRIu64 " B\n",
				min_free_ram);
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_NO_FREE_RAM);
	}

	ocf_pipeline_next(pipeline);
}


static void _ocf_mngt_load_superblock_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_cleaning_t loaded_clean_policy = cache->conf_meta->cleaning_policy_type;

	if (error) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cannot load cache state\n");
		OCF_PL_FINISH_RET(context->pipeline, error);
	}

	if (ocf_cache_get_line_count(cache) !=
			ocf_metadata_get_cachelines_count(cache)) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cache device size mismatch!\n");
		OCF_PL_FINISH_RET(context->pipeline,
				-OCF_ERR_START_CACHE_FAIL);
	}

	if (loaded_clean_policy >= ocf_cleaning_max) {
		ocf_cache_log(cache, log_err,
				"ERROR: Invalid cleaning policy!\n");
		OCF_PL_FINISH_RET(context->pipeline,
				-OCF_ERR_START_CACHE_FAIL);
	}

	__set_cleaning_policy(cache, loaded_clean_policy);

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_load_superblock(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_cache_log(cache, log_info, "Loading cache state...\n");
	if (context->metadata.shutdown_status == ocf_metadata_clean_shutdown) {
		ocf_metadata_load_superblock(cache,
				_ocf_mngt_load_superblock_complete, context);
	} else {
		ocf_metadata_load_superblock_recovery(cache,
				_ocf_mngt_load_superblock_complete, context);
	}
}

static void _ocf_mngt_attach_update_cores_atomic(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core;
	ocf_core_id_t core_id;
	ocf_seq_no_t core_sequence_no = 0;

	cache->conf_meta->curr_core_seq_no = 0;

	if (!ocf_volume_is_atomic(ocf_cache_get_volume(cache)))
			OCF_PL_NEXT_RET(pipeline);

	for_each_core_metadata(cache, core, core_id) {
		core_sequence_no = ocf_mngt_get_core_seq_no(cache);
		if (core_sequence_no == OCF_SEQ_NO_INVALID)
			OCF_PL_FINISH_RET(pipeline, -OCF_ERR_TOO_MANY_CORES);

		core->conf_meta->seq_no = core_sequence_no;
	}
}

static void _ocf_mngt_init_cleaner(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	result = ocf_start_cleaner(cache);
	if (result) {
		ocf_cache_log(cache, log_err,
				"Error while starting cleaner\n");
		OCF_PL_FINISH_RET(pipeline, result);
	}
	context->flags.cleaner_started = true;

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_init_promotion(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	result = ocf_promotion_init(cache, cache->conf_meta->promotion_policy_type);
	if (result) {
		ocf_cache_log(cache, log_err,
				"Cannot initialize promotion policy\n");
		OCF_PL_FINISH_RET(pipeline, result);
	}
	context->flags.promotion_initialized = true;

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_attach_zero_superblock_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"ERROR: Failed to clear superblock\n");
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_WRITE_CACHE);
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_attach_zero_superblock(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_metadata_zero_superblock(cache,
			_ocf_mngt_attach_zero_superblock_complete, context);
}

static void _ocf_mngt_attach_flush_metadata_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cannot save cache state\n");
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_WRITE_CACHE);
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_attach_flush_metadata(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_metadata_flush_all(cache,
			_ocf_mngt_attach_flush_metadata_complete, context);
}

static void _ocf_mngt_attach_discard_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	bool discard = cache->device->volume.features.discard_zeroes;

	if (error) {
		ocf_cache_log(cache, log_warn, "%s failed\n",
				discard ? "Discarding whole cache device" :
					"Overwriting cache with zeroes");

		if (ocf_volume_is_atomic(&cache->device->volume)) {
			ocf_cache_log(cache, log_err, "This step is required"
					" for atomic mode!\n");
			OCF_PL_FINISH_RET(context->pipeline, error);
		}

		ocf_cache_log(cache, log_warn, "This may impact cache"
				" performance!\n");
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_attach_discard(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	uint64_t addr = cache->device->metadata_offset;
	uint64_t length = ocf_volume_get_length(&cache->device->volume) - addr;
	bool discard = cache->device->volume.features.discard_zeroes;

	if (!context->cfg.discard_on_start)
		OCF_PL_NEXT_RET(pipeline);

	if (!discard && ocf_volume_is_atomic(&cache->device->volume)) {
		/* discard doesn't zero data - need to explicitly write zeros */
		ocf_submit_cache_write_zeros(cache, addr, length,
				_ocf_mngt_attach_discard_complete, context);
	} else {
		/* Discard volume after metadata */
		ocf_submit_cache_discard(cache, addr, length,
				_ocf_mngt_attach_discard_complete, context);
	}
}

static void _ocf_mngt_attach_flush_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static void _ocf_mngt_attach_flush(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	bool discard = cache->device->volume.features.discard_zeroes;

	if (!discard && ocf_volume_is_atomic(&cache->device->volume)) {
		ocf_submit_cache_flush(cache, _ocf_mngt_attach_flush_complete,
				context);
	} else {
		ocf_pipeline_next(pipeline);
	}
}

static void _ocf_mngt_attach_shutdown_status_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err, "Cannot flush shutdown status\n");
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_WRITE_CACHE);
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_attach_shutdown_status(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	/* clear clean shutdown status */
	ocf_metadata_set_shutdown_status(cache, ocf_metadata_dirty_shutdown,
		_ocf_mngt_attach_shutdown_status_complete, context);
}

static void _ocf_mngt_attach_disable_pt(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	env_refcnt_unfreeze(&cache->refcnt.d2c);

	env_atomic_set(&cache->attach_pt, 0);

	ocf_cache_log(cache, log_debug, "Cache attached\n");

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_attach_switch_to_pt(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	env_atomic_set(&cache->attach_pt, 1);

	ocf_cleaner_refcnt_unfreeze(cache);
	env_refcnt_unfreeze(&cache->refcnt.metadata);
	env_refcnt_freeze(&cache->refcnt.d2c);

	ocf_mngt_continue_pipeline_on_zero_refcnt(&cache->refcnt.d2c, pipeline);
}

static void _ocf_mngt_attach_handle_error(
		struct ocf_cache_attach_context *context)
{
	ocf_cache_t cache = context->cache;

	if (context->flags.cleaner_started)
		ocf_stop_cleaner(cache);

	if (context->flags.promotion_initialized)
		__deinit_promotion_policy(cache);

	if (context->flags.cleaning_initialized)
		__deinit_cleaning_policy(cache);

	if (context->flags.cores_opened)
		_ocf_mngt_deinit_added_cores(context);

	if (context->flags.attached_metadata_inited)
		ocf_metadata_deinit_variable_size(cache);

	if (context->flags.concurrency_inited)
		ocf_concurrency_deinit(cache);

	if (context->flags.volume_opened)
		ocf_volume_close(&cache->device->volume);

	if (context->flags.volume_inited)
		ocf_volume_deinit(&cache->device->volume);

	if (context->flags.front_volume_opened)
		ocf_volume_close(&cache->device->front_volume);

	if (context->flags.front_volume_inited)
		ocf_volume_deinit(&cache->device->front_volume);

	if (context->flags.device_alloc) {
		env_vfree(cache->device);
		cache->device = NULL;
	}

	if (context->flags.pio_concurrency)
		ocf_pio_concurrency_deinit(&cache->standby.concurrency);

	if (context->flags.pio_mpool)
		ocf_metadata_passive_io_ctx_deinit(cache);

	ocf_pipeline_destroy(cache->stop_pipeline);
}

static void _ocf_mngt_cache_attach_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	if (error)
		_ocf_mngt_attach_handle_error(context);

	context->cmpl(context->cache, context->priv1, context->priv2, error);

	ocf_pipeline_destroy(context->pipeline);
}

struct ocf_pipeline_properties _ocf_mngt_cache_attach_pipeline_properties = {
	.priv_size = sizeof(struct ocf_cache_attach_context),
	.finish = _ocf_mngt_cache_attach_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_init_attached_nonpersistent),
		OCF_PL_STEP(_ocf_mngt_attach_cache_device),
		OCF_PL_STEP(_ocf_mngt_init_properties),
		OCF_PL_STEP(_ocf_mngt_attach_read_properties),
		OCF_PL_STEP(_ocf_mngt_attach_check_ram),
		OCF_PL_STEP(_ocf_mngt_attach_prepare_metadata),
		OCF_PL_STEP(_ocf_mngt_test_volume),
		OCF_PL_STEP(_ocf_mngt_attach_update_cores_atomic),
		OCF_PL_STEP(_ocf_mngt_init_cleaner),
		OCF_PL_STEP(_ocf_mngt_init_promotion),
		OCF_PL_STEP(_ocf_mngt_attach_init_metadata),
		OCF_PL_STEP(_ocf_mngt_attach_populate_free),
		OCF_PL_STEP(_ocf_mngt_attach_init_services),
		OCF_PL_STEP(_ocf_mngt_attach_zero_superblock),
		OCF_PL_STEP(_ocf_mngt_attach_flush_metadata),
		OCF_PL_STEP(_ocf_mngt_attach_discard),
		OCF_PL_STEP(_ocf_mngt_attach_flush),
		OCF_PL_STEP(_ocf_mngt_attach_shutdown_status),
		OCF_PL_STEP(_ocf_mngt_attach_switch_to_pt),
		OCF_PL_STEP(_ocf_mngt_attach_disable_pt),
		OCF_PL_STEP_TERMINATOR(),
	},
};

struct ocf_pipeline_properties _ocf_mngt_cache_load_pipeline_properties = {
	.priv_size = sizeof(struct ocf_cache_attach_context),
	.finish = _ocf_mngt_cache_attach_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_init_attached_nonpersistent),
		OCF_PL_STEP(_ocf_mngt_attach_cache_device),
		OCF_PL_STEP(_ocf_mngt_init_properties),
		OCF_PL_STEP(_ocf_mngt_load_read_properties),
		OCF_PL_STEP(_ocf_mngt_attach_check_ram),
		OCF_PL_STEP(_ocf_mngt_attach_prepare_metadata),
		OCF_PL_STEP(_ocf_mngt_test_volume),
		OCF_PL_STEP(_ocf_mngt_load_superblock),
		OCF_PL_STEP(_ocf_mngt_init_cleaner),
		OCF_PL_STEP(_ocf_mngt_init_promotion),
		OCF_PL_STEP(_ocf_mngt_load_add_cores),
		OCF_PL_STEP(_ocf_mngt_load_init_structures),
		OCF_PL_STEP(_ocf_mngt_load_metadata),
		OCF_PL_STEP(_ocf_mngt_load_rebuild_metadata),
		OCF_PL_STEP(_ocf_mngt_load_init_cleaning),
		OCF_PL_STEP(_ocf_mngt_attach_shutdown_status),
		OCF_PL_STEP(_ocf_mngt_attach_flush_metadata),
		OCF_PL_STEP(_ocf_mngt_attach_shutdown_status),
		OCF_PL_STEP(_ocf_mngt_attach_switch_to_pt),
		OCF_PL_STEP(_ocf_mngt_attach_disable_pt),
		OCF_PL_STEP_TERMINATOR(),
	},
};

typedef void (*_ocf_mngt_cache_unplug_end_t)(void *context, int error);

struct ocf_mngt_cache_unplug_context {
	/* Fields that belong to cache stop pipeline */
	ocf_ctx_t ctx;
	char cache_name[OCF_CACHE_NAME_SIZE];
	bool close_volume;

	/* Fields that belong to cache detach pipeline */
	struct ocf_cleaner_wait_context cleaner_wait;
	bool detach_composite;
	uint8_t composite_vol_id;

	/* Fields that belong to both cache detach and cache stop pipelines */
	ocf_mngt_cache_stop_end_t cmpl;
	void *priv;
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
	int cache_write_error;
};

static void ocf_mngt_cache_stop_wait_metadata_io(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	struct env_refcnt *refcnt = &context->cache->refcnt.metadata;

	env_refcnt_freeze(refcnt);
	ocf_mngt_continue_pipeline_on_zero_refcnt(refcnt, context->pipeline);
}

static void ocf_mngt_cache_stop_check_dirty(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (ocf_mngt_cache_is_dirty(cache)) {
		cache->conf_meta->dirty_flushed = DIRTY_NOT_FLUSHED;

		ocf_cache_log(cache, log_warn, "Cache is still dirty. "
				"DO NOT USE your core devices until flushing "
				"dirty data!\n");
	} else {
		cache->conf_meta->dirty_flushed = DIRTY_FLUSHED;
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_cache_stop_remove_cores(ocf_cache_t cache)
{
	ocf_core_t core;
	ocf_core_id_t core_id;
	int no = cache->conf_meta->core_count;

	/* All exported objects removed, cleaning up rest. */
	for_each_core(cache, core, core_id) {
		cache_mngt_core_remove_from_cache(core);
		cache_mngt_core_deinit(core);
		if (--no == 0)
			break;
	}
}

static void ocf_mngt_cache_stop_remove_cores(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	_ocf_mngt_cache_stop_remove_cores(cache);

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_cache_deinit_services(ocf_cache_t cache)
{
	ocf_stop_cleaner(cache);

	__deinit_cleaning_policy(cache);
	__deinit_promotion_policy(cache);
}

static void ocf_mngt_cache_stop_deinit_services(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	_ocf_mngt_cache_deinit_services(cache);

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_stop_flush_metadata_completion(void *priv, int error)
{
	struct ocf_mngt_cache_unplug_context *context = priv;

	if (error)
		context->cache_write_error = -OCF_ERR_WRITE_CACHE;

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_stop_flush_metadata(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_metadata_flush_all(cache,
			ocf_mngt_cache_stop_flush_metadata_completion, context);
}

static void _ocf_mngt_detach_zero_superblock_complete(void *priv, int error)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"ERROR: Failed to clear the superblock on the detached device\n"
				"The metadata on the device is in an invalid state"
				" - manual superblock clearing is recommended.\n");
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_detach_zero_superblock(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_metadata_zero_superblock(cache,
			_ocf_mngt_detach_zero_superblock_complete, context);
}

static void _ocf_mngt_cache_put_io_queues(ocf_cache_t cache)
{
	ocf_queue_t queue, tmp_queue;

	list_for_each_entry_safe(queue, tmp_queue, &cache->io_queues, list)
		ocf_queue_put(queue);
}

static void ocf_mngt_cache_close_cache_volume(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_volume_close(&cache->device->volume);

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_deinit_cache_volume(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_volume_deinit(&cache->device->volume);

	env_vfree(cache->device);
	cache->device = NULL;

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_deinit_metadata(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_metadata_deinit_variable_size(cache);
	ocf_concurrency_deinit(cache);

	/* TODO: this should be removed from detach after 'attached' stats
		are better separated in statistics */
	env_atomic_set(&cache->fallback_pt_error_counter, 0);

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_stop_put_io_queues(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	_ocf_mngt_cache_put_io_queues(cache);

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_cache_dealloc(void *priv)
{
	ocf_cache_t cache = priv;
	ocf_ctx_t ctx;
	unsigned i;

	ctx = cache->owner;
	ocf_metadata_deinit(cache);

	env_refcnt_deinit(&cache->refcnt.cache);
	env_refcnt_deinit(&cache->refcnt.dirty);
	env_refcnt_deinit(&cache->refcnt.metadata);
	env_refcnt_deinit(&cache->refcnt.d2c);
	for (i = 0; i < OCF_USER_IO_CLASS_MAX; i++)
		env_refcnt_deinit(&cache->user_parts[i].cleaning.counter);

	env_vfree(cache);
	ocf_ctx_put(ctx);
}

static void ocf_mngt_cache_remove(ocf_ctx_t ctx, ocf_cache_t cache)
{
	/* Deinitialize cache lock */
	ocf_mngt_cache_lock_deinit(cache);

	/* Mark device uninitialized */
	env_refcnt_freeze(&cache->refcnt.cache);
	env_refcnt_register_zero_cb(&cache->refcnt.cache,
			     _ocf_mngt_cache_dealloc, cache);

	env_spinlock_destroy(&cache->io_queues_lock);

	env_mutex_destroy(&cache->flush_mutex);

	/* Remove cache from the list */
	env_rmutex_lock(&ctx->lock);
	list_del(&cache->list);
	env_rmutex_unlock(&ctx->lock);
}

static void ocf_mngt_cache_stop_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_ctx_t ctx = context->ctx;
	int pipeline_error;
	ocf_mngt_cache_stop_end_t pipeline_cmpl;
	void *completion_priv;

	if (!error) {
		ocf_mngt_cache_remove(context->ctx, cache);
	} else {
		/* undo metadata counter freeze */
		env_refcnt_unfreeze(&cache->refcnt.metadata);

		env_bit_clear(ocf_cache_state_stopping, &cache->cache_state);
		env_bit_set(ocf_cache_state_running, &cache->cache_state);
	}

	if (!error) {
		if (!context->cache_write_error) {
			ocf_log(ctx, log_info,
					"Cache %s successfully stopped\n",
					context->cache_name);
		} else {
			ocf_log(ctx, log_warn, "Stopped cache %s with errors\n",
					context->cache_name);
		}
	} else {
		ocf_log(ctx, log_err, "Stopping cache %s failed\n",
				context->cache_name);
	}

	/*
	 * FIXME: Destroying pipeline before completing management operation is a
	 * temporary workaround for insufficient object lifetime management in pyocf
	 * Context must not be referenced after destroying pipeline as this is
	 * typically freed upon pipeline destroy.
	 */
	pipeline_error = error ?: context->cache_write_error;
	pipeline_cmpl = context->cmpl;
	completion_priv = context->priv;

	ocf_pipeline_destroy(context->pipeline);

	pipeline_cmpl(cache, completion_priv, pipeline_error);

	if (!error) {
		/* Finally release cache instance */
		ocf_mngt_cache_put(cache);
	}
}

struct ocf_pipeline_properties ocf_mngt_cache_stop_pipeline_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_unplug_context),
	.finish = ocf_mngt_cache_stop_finish,
	.steps = {
		OCF_PL_STEP(ocf_mngt_cache_stop_wait_metadata_io),
		OCF_PL_STEP(ocf_mngt_cache_stop_check_dirty),
		OCF_PL_STEP(ocf_mngt_cache_stop_deinit_services),
		OCF_PL_STEP(ocf_mngt_cache_stop_remove_cores),
		OCF_PL_STEP(ocf_mngt_cache_stop_flush_metadata),
		OCF_PL_STEP(ocf_mngt_cache_close_cache_volume),
		OCF_PL_STEP(ocf_mngt_cache_deinit_metadata),
		OCF_PL_STEP(ocf_mngt_cache_deinit_cache_volume),
		OCF_PL_STEP(ocf_mngt_cache_stop_put_io_queues),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void _ocf_mngt_init_cache_front_volume(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_volume_type_t type;
	struct ocf_volume_uuid uuid = {
		.data = cache,
		.size = sizeof(cache),
	};
	int result;

	type = ocf_ctx_get_volume_type_internal(cache->owner, OCF_VOLUME_TYPE_CACHE);
	if (!type)
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_INVAL);

	result = ocf_volume_init(&cache->device->front_volume, type, &uuid, false);
	if (result)
		OCF_PL_FINISH_RET(context->pipeline, result);
	cache->device->front_volume.cache = cache;
	context->flags.front_volume_inited = true;

	result = ocf_volume_open(&cache->device->front_volume, NULL);
	if (result)
		OCF_PL_FINISH_RET(context->pipeline, result);
	context->flags.front_volume_opened = true;

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_standby_init_properties(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	OCF_ASSERT_PLUGGED(cache);

	context->metadata.shutdown_status = ocf_metadata_dirty_shutdown;
	context->metadata.dirty_flushed = DIRTY_FLUSHED;
	context->metadata.line_size = context->cfg.cache_line_size ?:
			cache->metadata.line_size;
	context->metadata.cleaner_disabled = context->cfg.disable_cleaner;

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_standby_prepare_mempool(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	result = ocf_metadata_passive_io_ctx_init(cache);
	if(!result)
		context->flags.pio_mpool = true;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, result);
}

static void _ocf_mngt_standby_init_structures_attach(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	init_attached_data_structures_recovery(cache,
			_ocf_mngt_init_metadata_complete, context, false);
}

static void _ocf_mngt_standby_init_structures_load(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	init_attached_data_structures_recovery(cache,
			_ocf_mngt_init_metadata_complete, context, true);
}

static void _ocf_mngt_standby_init_pio_concurrency(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	result = ocf_pio_concurrency_init(&cache->standby.concurrency, cache);
	if (!result)
		context->flags.pio_concurrency = true;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, result);
}

static void _ocf_mngt_standby_post_init(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	env_refcnt_unfreeze(&cache->refcnt.metadata);

	ocf_pipeline_next(pipeline);
}

struct ocf_pipeline_properties _ocf_mngt_cache_standby_attach_pipeline_properties = {
	.priv_size = sizeof(struct ocf_cache_attach_context),
	.finish = _ocf_mngt_cache_attach_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_init_attached_nonpersistent),
		OCF_PL_STEP(_ocf_mngt_attach_cache_device),
		OCF_PL_STEP(_ocf_mngt_attach_read_properties),
		OCF_PL_STEP(_ocf_mngt_standby_init_properties),
		OCF_PL_STEP(_ocf_mngt_init_cache_front_volume),
		OCF_PL_STEP(_ocf_mngt_attach_check_ram),
		OCF_PL_STEP(_ocf_mngt_attach_prepare_metadata),
		OCF_PL_STEP(_ocf_mngt_test_volume),
		OCF_PL_STEP(_ocf_mngt_init_cleaner),
		OCF_PL_STEP(_ocf_mngt_standby_init_structures_attach),
		OCF_PL_STEP(_ocf_mngt_attach_populate_free),
		OCF_PL_STEP(_ocf_mngt_standby_prepare_mempool),
		OCF_PL_STEP(_ocf_mngt_standby_init_pio_concurrency),
		OCF_PL_STEP(_ocf_mngt_attach_zero_superblock),
		OCF_PL_STEP(_ocf_mngt_attach_flush_metadata),
		OCF_PL_STEP(_ocf_mngt_attach_discard),
		OCF_PL_STEP(_ocf_mngt_attach_flush),
		OCF_PL_STEP(_ocf_mngt_standby_post_init),
		OCF_PL_STEP_TERMINATOR(),
	},
};

struct ocf_pipeline_properties _ocf_mngt_cache_standby_load_pipeline_properties = {
	.priv_size = sizeof(struct ocf_cache_attach_context),
	.finish = _ocf_mngt_cache_attach_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_init_attached_nonpersistent),
		OCF_PL_STEP(_ocf_mngt_attach_cache_device),
		OCF_PL_STEP(_ocf_mngt_init_cache_front_volume),
		OCF_PL_STEP(_ocf_mngt_standby_init_properties),
		OCF_PL_STEP(_ocf_mngt_attach_check_ram),
		OCF_PL_STEP(_ocf_mngt_test_volume),
		OCF_PL_STEP(_ocf_mngt_attach_prepare_metadata),
		OCF_PL_STEP(_ocf_mngt_load_superblock),
		OCF_PL_STEP(_ocf_mngt_load_metadata_recovery),
		OCF_PL_STEP(_ocf_mngt_init_cleaner),
		OCF_PL_STEP(_ocf_mngt_standby_prepare_mempool),
		OCF_PL_STEP(_ocf_mngt_standby_init_pio_concurrency),
		OCF_PL_STEP(_ocf_mngt_load_rebuild_metadata),
		OCF_PL_STEP(_ocf_mngt_standby_post_init),
		OCF_PL_STEP_TERMINATOR(),
	},
};

struct ocf_cache_standby_detach_context {
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
	ocf_mngt_cache_standby_detach_end_t cmpl;
	void *priv;
};

static void _ocf_mngt_standby_detach_wait_metadata_io(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_standby_detach_context *context = priv;
	struct env_refcnt *refcnt = &context->cache->refcnt.metadata;

	env_refcnt_freeze(refcnt);
	ocf_mngt_continue_pipeline_on_zero_refcnt(refcnt, context->pipeline);
}

static void _ocf_mngt_activate_set_cache_device(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	struct ocf_mngt_cache_device_config *device_cfg = &context->cfg.device;
	ocf_cache_t cache = context->cache;
	int ret;

	ret = ocf_volume_init(&cache->device->volume, device_cfg->volume->type,
			NULL, false);
	if (ret)
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_NO_MEM);

	context->flags.volume_inited = true;

	ocf_volume_move(&cache->device->volume, device_cfg->volume);
	cache->device->volume.cache = cache;

	ret = ocf_volume_open(&cache->device->volume,
			device_cfg->volume_params);
	if (ret) {
		ocf_cache_log(cache, log_err, "ERROR: Cache not available\n");
		OCF_PL_FINISH_RET(pipeline, ret);
	}
	context->flags.volume_opened = true;

	context->volume_size = ocf_volume_get_length(&cache->device->volume);

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_activate_check_superblock(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	result = ocf_metadata_validate_superblock(cache->owner,
			cache->conf_meta);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);

	if (cache->conf_meta->line_size != cache->metadata.line_size) {
		ocf_cache_log(cache, log_err, "Failed to activate standby instance: "
				"invaild cache line size\n");
		OCF_PL_FINISH_RET(context->pipeline,
				-OCF_ERR_CACHE_LINE_SIZE_MISMATCH);
	}

	if (env_strncmp(cache->conf_meta->name, OCF_CACHE_NAME_SIZE,
				cache->name, OCF_CACHE_NAME_SIZE)) {
		ocf_cache_log(cache, log_err, "Failed to activate standby instance: "
				"cache name mismtach\n");
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_CACHE_NAME_MISMATCH);
	}

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_activate_compare_superblock_end(
		struct ocf_metadata_read_sb_ctx *sb_ctx)
{
	struct ocf_superblock_config *superblock = &sb_ctx->superblock;
	struct ocf_cache_attach_context *context = sb_ctx->priv1;
	ocf_cache_t cache = context->cache;
	int result, diff;

	if (sb_ctx->error)
		OCF_PL_FINISH_RET(context->pipeline, sb_ctx->error);

	result = env_memcmp(cache->conf_meta, sizeof(*cache->conf_meta),
			superblock, sizeof(*superblock), &diff);
	if (result)
		OCF_PL_FINISH_RET(context->pipeline, result);

	if (diff) {
		if (cache->conf_meta->line_size != superblock->line_size) {
                	ocf_cache_log(cache, log_err, "Superblock mismatch. Cache line size in RAM: %lu KiB. "
                                "Cache line size on disk: %lu KiB.\n", cache->conf_meta->line_size, superblock->line_size);
			OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_CACHE_LINE_SIZE_MISMATCH);
		}

		ocf_cache_log(cache, log_err, "Superblock mismatch!\n");
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_SUPERBLOCK_MISMATCH);
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_activate_compare_superblock(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	result = ocf_metadata_read_sb(cache->owner, ocf_cache_get_volume(cache),
			_ocf_mngt_activate_compare_superblock_end,
			context, NULL);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);
}

static void _ocf_mngt_activate_init_properties(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	OCF_ASSERT_PLUGGED(cache);

	context->metadata.shutdown_status = ocf_metadata_dirty_shutdown;
	context->metadata.dirty_flushed = DIRTY_NOT_FLUSHED;
	context->metadata.line_size = cache->metadata.line_size;

	ocf_pipeline_next(pipeline);
}

static void _ocf_mngt_activate_handle_error(
		struct ocf_cache_attach_context *context)
{
	ocf_cache_t cache = context->cache;

	if (context->flags.promotion_initialized)
		__deinit_promotion_policy(cache);

	if (context->flags.cores_opened)
		_ocf_mngt_deinit_added_cores(context);

	if (context->flags.volume_opened)
		ocf_volume_close(&cache->device->volume);

	if (context->flags.volume_inited)
		ocf_volume_deinit(&cache->device->volume);

	if (context->flags.metadata_frozen)
		env_refcnt_unfreeze(&cache->refcnt.metadata);
}

static void _ocf_mngt_cache_activate_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_pipeline_t stop_pipeline;

	if (error) {
		_ocf_mngt_activate_handle_error(context);
		goto out;
	}

	error = ocf_pipeline_create(&stop_pipeline, cache,
			&ocf_mngt_cache_stop_pipeline_properties);
	if (error) {
		_ocf_mngt_activate_handle_error(context);
		goto out;
	}

	ocf_pipeline_destroy(cache->stop_pipeline);
	cache->stop_pipeline = stop_pipeline;

out:
	context->cmpl(context->cache, context->priv1, context->priv2, error);

	ocf_pipeline_destroy(context->pipeline);
}

struct ocf_pipeline_properties _ocf_mngt_cache_activate_pipeline_properties = {
	.priv_size = sizeof(struct ocf_cache_attach_context),
	.finish = _ocf_mngt_cache_activate_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_activate_set_cache_device),
		OCF_PL_STEP(_ocf_mngt_activate_init_properties),
		OCF_PL_STEP(_ocf_mngt_activate_compare_superblock),
		OCF_PL_STEP(_ocf_mngt_load_superblock),
		OCF_PL_STEP(_ocf_mngt_activate_check_superblock),
		OCF_PL_STEP(_ocf_mngt_activate_init_properties),
		OCF_PL_STEP(_ocf_mngt_test_volume),
		OCF_PL_STEP(_ocf_mngt_init_promotion),
		OCF_PL_STEP(_ocf_mngt_load_add_cores),
		OCF_PL_STEP(_ocf_mngt_standby_init_structures_load),
		OCF_PL_STEP(_ocf_mngt_load_rebuild_metadata),
		OCF_PL_STEP(_ocf_mngt_load_init_cleaning),
		OCF_PL_STEP(_ocf_mngt_attach_shutdown_status),
		OCF_PL_STEP(_ocf_mngt_attach_switch_to_pt),
		OCF_PL_STEP(_ocf_mngt_attach_disable_pt),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void _ocf_mngt_cache_attach(ocf_cache_t cache,
		struct ocf_mngt_cache_attach_config *cfg,
		_ocf_mngt_cache_attach_end_t cmpl, void *priv1, void *priv2)
{
	struct ocf_cache_attach_context *context;
	ocf_pipeline_t pipeline;
	int result;

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_cache_attach_pipeline_properties);
	if (result)
		OCF_CMPL_RET(cache, priv1, priv2, -OCF_ERR_NO_MEM);

	result = ocf_pipeline_create(&cache->stop_pipeline, cache,
			&ocf_mngt_cache_stop_pipeline_properties);
	if (result) {
		ocf_pipeline_destroy(pipeline);
		OCF_CMPL_RET(cache, priv1, priv2, -OCF_ERR_NO_MEM);
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv1 = priv1;
	context->priv2 = priv2;
	context->pipeline = pipeline;

	context->cache = cache;
	memcpy(&context->cfg, cfg, sizeof(context->cfg));

	OCF_PL_NEXT_RET(pipeline);
}

static void _ocf_mngt_cache_load(ocf_cache_t cache,
		struct ocf_mngt_cache_attach_config *cfg,
		_ocf_mngt_cache_attach_end_t cmpl, void *priv1, void *priv2)
{
	struct ocf_cache_attach_context *context;
	ocf_pipeline_t pipeline;
	int result;

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_cache_load_pipeline_properties);
	if (result)
		OCF_CMPL_RET(cache, priv1, priv2, -OCF_ERR_NO_MEM);

	result = ocf_pipeline_create(&cache->stop_pipeline, cache,
			&ocf_mngt_cache_stop_pipeline_properties);
	if (result) {
		ocf_pipeline_destroy(pipeline);
		OCF_CMPL_RET(cache, priv1, priv2, -OCF_ERR_NO_MEM);
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv1 = priv1;
	context->priv2 = priv2;
	context->pipeline = pipeline;

	context->cache = cache;
	memcpy(&context->cfg, cfg, sizeof(context->cfg));

	OCF_PL_NEXT_RET(pipeline);
}

static void ocf_mngt_stop_standby_stop_prepare(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	context->close_volume = !env_refcnt_frozen(&cache->refcnt.metadata);

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_stop_standby_stop_cleaner(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_stop_cleaner(cache);

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_standby_close_cache_volume(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (context->close_volume)
		ocf_volume_close(&cache->device->volume);

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_standby_deinit_pio(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_metadata_passive_io_ctx_deinit(cache);
	ocf_pio_concurrency_deinit(&cache->standby.concurrency);

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_standby_deinit_cache_volume(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (!env_refcnt_frozen(&cache->refcnt.metadata)) {
		ocf_volume_deinit(&cache->device->volume);

		env_vfree(cache->device);
		cache->device = NULL;
	}

	ocf_pipeline_next(pipeline);
}

struct ocf_pipeline_properties
ocf_mngt_cache_stop_standby_pipeline_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_unplug_context),
	.finish = ocf_mngt_cache_stop_finish,
	.steps = {
		OCF_PL_STEP(ocf_mngt_stop_standby_stop_prepare),
		OCF_PL_STEP(ocf_mngt_cache_stop_wait_metadata_io),
		OCF_PL_STEP(ocf_mngt_stop_standby_stop_cleaner),
		OCF_PL_STEP(ocf_mngt_cache_standby_close_cache_volume),
		OCF_PL_STEP(ocf_mngt_cache_deinit_metadata),
		OCF_PL_STEP(ocf_mngt_cache_standby_deinit_cache_volume),
		OCF_PL_STEP(ocf_mngt_cache_stop_put_io_queues),
		OCF_PL_STEP(ocf_mngt_cache_standby_deinit_pio),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void _ocf_mngt_cache_standby_attach(ocf_cache_t cache,
		struct ocf_mngt_cache_attach_config *cfg,
		_ocf_mngt_cache_attach_end_t cmpl, void *priv1, void *priv2)
{
	struct ocf_cache_attach_context *context;
	ocf_pipeline_t pipeline;
	int result;

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_cache_standby_attach_pipeline_properties);
	if (result)
		OCF_CMPL_RET(cache, priv1, priv2, -OCF_ERR_NO_MEM);

	result = ocf_pipeline_create(&cache->stop_pipeline, cache,
			&ocf_mngt_cache_stop_standby_pipeline_properties);
	if (result) {
		ocf_pipeline_destroy(pipeline);
		OCF_CMPL_RET(cache, priv1, priv2, -OCF_ERR_NO_MEM);
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv1 = priv1;
	context->priv2 = priv2;
	context->pipeline = pipeline;

	context->cache = cache;
	memcpy(&context->cfg, cfg, sizeof(context->cfg));

	OCF_PL_NEXT_RET(pipeline);
}

static void _ocf_mngt_cache_standby_load(ocf_cache_t cache,
		struct ocf_mngt_cache_attach_config *cfg,
		_ocf_mngt_cache_attach_end_t cmpl, void *priv1, void *priv2)
{
	struct ocf_cache_attach_context *context;
	ocf_pipeline_t pipeline;
	int result;

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_cache_standby_load_pipeline_properties);
	if (result)
		OCF_CMPL_RET(cache, priv1, priv2, -OCF_ERR_NO_MEM);

	result = ocf_pipeline_create(&cache->stop_pipeline, cache,
			&ocf_mngt_cache_stop_standby_pipeline_properties);
	if (result) {
		ocf_pipeline_destroy(pipeline);
		OCF_CMPL_RET(cache, priv1, priv2, -OCF_ERR_NO_MEM);
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv1 = priv1;
	context->priv2 = priv2;
	context->pipeline = pipeline;

	context->cache = cache;
	memcpy(&context->cfg, cfg, sizeof(context->cfg));

	OCF_PL_NEXT_RET(pipeline);
}

static void _ocf_mngt_standby_detach_close_volume(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_standby_detach_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_volume_close(&cache->device->volume);
	ocf_volume_deinit(&cache->device->volume);

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_standby_detach_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_cache_standby_detach_context *context = priv;

	context->cmpl(context->priv, error);

	ocf_pipeline_destroy(context->pipeline);
}

struct ocf_pipeline_properties
_ocf_mngt_cache_standby_detach_pipeline_properties = {
	.priv_size = sizeof(struct ocf_cache_standby_detach_context),
	.finish = ocf_mngt_cache_standby_detach_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_standby_detach_wait_metadata_io),
		OCF_PL_STEP(_ocf_mngt_standby_detach_close_volume),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void _ocf_mngt_cache_standby_detach(ocf_cache_t cache,
		ocf_mngt_cache_standby_detach_end_t cmpl, void *priv)
{
	struct ocf_cache_standby_detach_context *context;
	ocf_pipeline_t pipeline;
	int result;

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_cache_standby_detach_pipeline_properties);
	if (result)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;

	context->cache = cache;

	OCF_PL_NEXT_RET(pipeline);
}

static void _ocf_mngt_cache_standby_activate(ocf_cache_t cache,
		struct ocf_mngt_cache_standby_activate_config *cfg,
		_ocf_mngt_cache_attach_end_t cmpl, void *priv1, void *priv2)
{
	struct ocf_cache_attach_context *context;
	ocf_pipeline_t pipeline;
	int result;

	if (!ocf_cache_is_standby(cache))
		OCF_CMPL_RET(cache, priv1, priv2, -OCF_ERR_CACHE_EXIST);

	if (!env_refcnt_frozen(&cache->refcnt.metadata))
		OCF_CMPL_RET(cache, priv1, priv2, OCF_ERR_STANDBY_ATTACHED);

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_cache_activate_pipeline_properties);
	if (result)
		OCF_CMPL_RET(cache, priv1, priv2, -OCF_ERR_NO_MEM);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv1 = priv1;
	context->priv2 = priv2;
	context->pipeline = pipeline;
	context->cache = cache;

	context->cfg.device = cfg->device;
	context->cfg.cache_line_size = cache->metadata.line_size;
	context->cfg.open_cores = cfg->open_cores;
	context->cfg.force = false;
	context->cfg.discard_on_start = false;

	OCF_PL_NEXT_RET(pipeline);
}

static int _ocf_mngt_cache_validate_cfg(struct ocf_mngt_cache_config *cfg)
{
	if (!strnlen(cfg->name, OCF_CACHE_NAME_SIZE))
		return -OCF_ERR_INVAL;

	if (!ocf_cache_mode_is_valid(cfg->cache_mode))
		return -OCF_ERR_INVALID_CACHE_MODE;

	if (cfg->promotion_policy >= ocf_promotion_max ||
			cfg->promotion_policy < 0 ) {
		return -OCF_ERR_INVAL;
	}

	if (!ocf_cache_line_size_is_valid(cfg->cache_line_size))
		return -OCF_ERR_INVALID_CACHE_LINE_SIZE;

	if (cfg->backfill.queue_unblock_size > cfg->backfill.max_queue_size )
		return -OCF_ERR_INVAL;

	return 0;
}

static int _ocf_mngt_cache_validate_device_cfg(
		struct ocf_mngt_cache_device_config *device_cfg)
{
	if (!device_cfg->volume)
		return -OCF_ERR_INVAL;

	return 0;
}

static int _ocf_mngt_cache_validate_attach_cfg(
		struct ocf_mngt_cache_attach_config *attach_cfg)
{
	int ret;

	ret = _ocf_mngt_cache_validate_device_cfg(&attach_cfg->device);
	if (ret)
		return ret;

	if (attach_cfg->cache_line_size != ocf_cache_line_size_none &&
		!ocf_cache_line_size_is_valid(attach_cfg->cache_line_size))
		return -OCF_ERR_INVALID_CACHE_LINE_SIZE;

	return 0;
}

static const char *_ocf_cache_mode_names[ocf_cache_mode_max] = {
	[ocf_cache_mode_wt] = "wt",
	[ocf_cache_mode_wb] = "wb",
	[ocf_cache_mode_wa] = "wa",
	[ocf_cache_mode_pt] = "pt",
	[ocf_cache_mode_wi] = "wi",
	[ocf_cache_mode_wo] = "wo",
};

static const char *_ocf_cache_mode_get_name(ocf_cache_mode_t cache_mode)
{
	if (!ocf_cache_mode_is_valid(cache_mode))
		return NULL;

	return _ocf_cache_mode_names[cache_mode];
}

int ocf_mngt_cache_start(ocf_ctx_t ctx, ocf_cache_t *cache,
		struct ocf_mngt_cache_config *cfg, void *priv)
{
	int result;

	if (!ctx || !cache || !cfg)
		return -OCF_ERR_INVAL;

	result = _ocf_mngt_cache_validate_cfg(cfg);
	if (result)
		return result;

	result = _ocf_mngt_cache_start(ctx, cache, cfg, priv);
	if (!result) {
		ocf_cache_log(*cache, log_info, "Successfully added\n");
		ocf_cache_log(*cache, log_info, "Cache mode : %s\n",
			_ocf_cache_mode_get_name(ocf_cache_get_mode(*cache)));
	} else
		ocf_log(ctx, log_err, "%s: Inserting cache failed\n", cfg->name);

	return result;
}

static void _ocf_mngt_cache_attach_complete(ocf_cache_t cache, void *priv1,
		void *priv2, int error)
{
	ocf_mngt_cache_attach_end_t cmpl = priv1;

	if (!error) {
		_ocf_mngt_cache_set_valid(cache);
		ocf_cache_log(cache, log_info, "Successfully attached\n");
	} else {
		ocf_cache_log(cache, log_err, "Attaching cache device "
				   "failed\n");
	}

	OCF_CMPL_RET(cache, priv2, error);
}

void ocf_mngt_cache_attach(ocf_cache_t cache,
		struct ocf_mngt_cache_attach_config *cfg,
		ocf_mngt_cache_attach_end_t cmpl, void *priv)
{
	int result;

	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(cfg);

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_STANDBY);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	if (ocf_cache_is_device_attached(cache)) {
		ocf_cache_log(cache, log_err, "Cache is already attached!\n");
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);
	}

	result = _ocf_mngt_cache_validate_attach_cfg(cfg);
	if (result)
		OCF_CMPL_RET(cache, priv, result);

	_ocf_mngt_cache_attach(cache, cfg, _ocf_mngt_cache_attach_complete, cmpl, priv);
}

static int _ocf_mngt_cache_load_core_log(ocf_core_t core, void *cntx)
{
	if (ocf_core_state_active == ocf_core_get_state(core))
		ocf_core_log(core, log_info, "Successfully added\n");
	else
		ocf_core_log(core, log_warn, "Failed to initialize\n");

	return 0;
}

static void _ocf_mngt_cache_load_log(ocf_cache_t cache)
{
	ocf_cache_mode_t cache_mode = ocf_cache_get_mode(cache);
	ocf_cleaning_t cleaning_type = cache->cleaner.policy;
	ocf_promotion_t promotion_type = cache->conf_meta->promotion_policy_type;

	ocf_cache_log(cache, log_info, "Successfully loaded\n");
	ocf_cache_log(cache, log_info, "Cache mode : %s\n",
			_ocf_cache_mode_get_name(cache_mode));
	ocf_cache_log(cache, log_info, "Cleaning policy : %s\n",
			ocf_cleaning_get_name(cleaning_type));
	ocf_cache_log(cache, log_info, "Promotion policy : %s\n",
			ocf_promotion_policies[promotion_type].name);
	ocf_core_visit(cache, _ocf_mngt_cache_load_core_log,
			cache, false);
}

static void _ocf_mngt_cache_load_complete(ocf_cache_t cache, void *priv1,
		void *priv2, int error)
{
	ocf_mngt_cache_load_end_t cmpl = priv1;

	if (error)
		OCF_CMPL_RET(cache, priv2, error);

	_ocf_mngt_cache_set_valid(cache);
	_ocf_mngt_cache_load_log(cache);

	OCF_CMPL_RET(cache, priv2, 0);
}

void ocf_mngt_cache_load(ocf_cache_t cache,
		struct ocf_mngt_cache_attach_config *cfg,
		ocf_mngt_cache_load_end_t cmpl, void *priv)
{
	int result;

	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(cfg);

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_STANDBY);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	/* Load is not allowed in volatile metadata mode */
	if (cache->metadata.is_volatile)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	/* Load is not allowed with 'force' flag on */
	if (cfg->force) {
		ocf_cache_log(cache, log_err, "Using 'force' flag is forbidden "
				"for load operation.");
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);
	}

	result = _ocf_mngt_cache_validate_attach_cfg(cfg);
	if (result)
		OCF_CMPL_RET(cache, priv, result);

	_ocf_mngt_cache_load(cache, cfg, _ocf_mngt_cache_load_complete, cmpl, priv);
}

static void _ocf_mngt_cache_standby_attach_complete(ocf_cache_t cache,
		void *priv1, void *priv2, int error)
{
	ocf_mngt_cache_standby_attach_end_t cmpl = priv1;

	if (error)
		OCF_CMPL_RET(cache, priv2, error);

	_ocf_mngt_cache_set_standby(cache);
	ocf_cache_log(cache, log_info, "Successfully attached standby cache\n");

	OCF_CMPL_RET(cache, priv2, 0);
}

void ocf_mngt_cache_standby_attach(ocf_cache_t cache,
		struct ocf_mngt_cache_attach_config *cfg,
		ocf_mngt_cache_standby_attach_end_t cmpl, void *priv)
{
	int result;

	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(cfg);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	/* Standby is not allowed in volatile metadata mode */
	if (cache->metadata.is_volatile)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	result = _ocf_mngt_cache_validate_attach_cfg(cfg);
	if (result)
		OCF_CMPL_RET(cache, priv, result);

	_ocf_mngt_cache_standby_attach(cache, cfg,
			_ocf_mngt_cache_standby_attach_complete, cmpl, priv);
}

static void _ocf_mngt_cache_standby_load_complete(ocf_cache_t cache,
		void *priv1, void *priv2, int error)
{
	ocf_mngt_cache_standby_attach_end_t cmpl = priv1;

	if (error)
		OCF_CMPL_RET(cache, priv2, error);

	_ocf_mngt_cache_set_standby(cache);
	ocf_cache_log(cache, log_info, "Successfully loaded standby cache\n");

	OCF_CMPL_RET(cache, priv2, 0);
}

void ocf_mngt_cache_standby_load(ocf_cache_t cache,
		struct ocf_mngt_cache_attach_config *cfg,
		ocf_mngt_cache_standby_load_end_t cmpl, void *priv)
{
	int result;

	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(cfg);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	/* Standby is not allowed in volatile metadata mode */
	if (cache->metadata.is_volatile)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	/* Standby load is not allowed with 'force' flag on */
	if (cfg->force) {
		ocf_cache_log(cache, log_err, "Using 'force' flag is forbidden "
				"for standby load operation.");
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);
	}

	result = _ocf_mngt_cache_validate_attach_cfg(cfg);
	if (result)
		OCF_CMPL_RET(cache, priv, result);

	_ocf_mngt_cache_standby_load(cache, cfg,
			_ocf_mngt_cache_standby_load_complete, cmpl, priv);
}

void ocf_mngt_cache_standby_detach(ocf_cache_t cache,
		ocf_mngt_cache_standby_detach_end_t cmpl, void *priv)
{
	OCF_CHECK_NULL(cache);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL);

	if (!ocf_cache_is_standby(cache))
		OCF_CMPL_RET(priv, -OCF_ERR_CACHE_EXIST);

	if (env_refcnt_frozen(&cache->refcnt.metadata))
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL);

	_ocf_mngt_cache_standby_detach(cache, cmpl, priv);
}

static void _ocf_mngt_cache_standby_activate_complete(ocf_cache_t cache,
		void *priv1, void *priv2, int error)
{
	ocf_mngt_cache_standby_activate_end_t cmpl = priv1;

	if (error)
		OCF_CMPL_RET(cache, priv2, error);

	_ocf_mngt_cache_set_active(cache);
	ocf_cache_log(cache, log_info, "Successfully activated\n");

	ocf_pio_concurrency_deinit(&cache->standby.concurrency);
	ocf_metadata_passive_io_ctx_deinit(cache);

	OCF_CMPL_RET(cache, priv2, 0);
}

void ocf_mngt_cache_standby_activate(ocf_cache_t cache,
		struct ocf_mngt_cache_standby_activate_config *cfg,
		ocf_mngt_cache_standby_activate_end_t cmpl, void *priv)
{
	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(cfg);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	if (_ocf_mngt_cache_validate_device_cfg(&cfg->device))
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	_ocf_mngt_cache_standby_activate(cache, cfg,
			_ocf_mngt_cache_standby_activate_complete,
			cmpl, priv);
}

static void ocf_mngt_cache_stop_detached(ocf_cache_t cache,
		ocf_mngt_cache_stop_end_t cmpl, void *priv)
{
	_ocf_mngt_cache_stop_remove_cores(cache);
	_ocf_mngt_cache_put_io_queues(cache);
	ocf_mngt_cache_remove(cache->owner, cache);
	ocf_cache_log(cache, log_info, "Cache %s successfully stopped\n",
			ocf_cache_get_name(cache));
	cmpl(cache, priv, 0);
	ocf_mngt_cache_put(cache);
}

void ocf_mngt_cache_stop(ocf_cache_t cache,
		ocf_mngt_cache_stop_end_t cmpl, void *priv)
{
	struct ocf_mngt_cache_unplug_context *context;
	ocf_pipeline_t pipeline;

	OCF_CHECK_NULL(cache);

	if (!ocf_cache_is_device_attached(cache)) {
		env_bit_set(ocf_cache_state_stopping, &cache->cache_state);
		env_bit_clear(ocf_cache_state_detached, &cache->cache_state);
		ocf_mngt_cache_stop_detached(cache, cmpl, priv);
		return;
	}

	ENV_BUG_ON(!cache->mngt_queue);

	pipeline = cache->stop_pipeline;
	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->ctx = cache->owner;

	ENV_BUG_ON(env_strncpy(context->cache_name, sizeof(context->cache_name),
			ocf_cache_get_name(cache), sizeof(context->cache_name)));

	ocf_cache_log(cache, log_info, "Stopping cache\n");

	env_bit_set(ocf_cache_state_stopping, &cache->cache_state);
	env_bit_clear(ocf_cache_state_running, &cache->cache_state);

	ocf_pipeline_next(pipeline);
}

struct ocf_mngt_cache_save_context {
	ocf_mngt_cache_save_end_t cmpl;
	void *priv;
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
};

static void ocf_mngt_cache_save_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_mngt_cache_save_context *context = priv;

	context->cmpl(context->cache, context->priv, error);

	ocf_pipeline_destroy(context->pipeline);
}

struct ocf_pipeline_properties ocf_mngt_cache_save_pipeline_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_save_context),
	.finish = ocf_mngt_cache_save_finish,
	.steps = {
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void ocf_mngt_cache_save_flush_sb_complete(void *priv, int error)
{
	struct ocf_mngt_cache_save_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"Failed to flush superblock! Changes "
				"in cache config are not persistent!\n");
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_WRITE_CACHE);
	}

	ocf_pipeline_next(context->pipeline);
}

void ocf_mngt_cache_save(ocf_cache_t cache,
		ocf_mngt_cache_save_end_t cmpl, void *priv)
{
	struct ocf_mngt_cache_save_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_CHECK_NULL(cache);

	if (!ocf_cache_is_device_attached(cache)) {
		ocf_cache_log(cache, log_info, "Cache is in detached state. Any changes"
				" made to the cache configuration won't persist through cache "
				"stop unless a caching volume is attached\n");
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_DETACHED);
	}

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_STANDBY);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_mngt_cache_save_pipeline_properties);
	if (result)
		OCF_CMPL_RET(cache, priv, result);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	ocf_metadata_flush_superblock(cache,
			ocf_mngt_cache_save_flush_sb_complete, context);
}

static void _cache_mngt_update_initial_dirty_clines(ocf_cache_t cache)
{
	ocf_core_t core;
	ocf_core_id_t core_id;

	for_each_core(cache, core, core_id) {
		env_atomic_set(&core->runtime_meta->initial_dirty_clines,
				env_atomic_read(&core->runtime_meta->
						dirty_clines));
	}

}

static int _cache_mngt_set_cache_mode(ocf_cache_t cache, ocf_cache_mode_t mode)
{
	ocf_cache_mode_t mode_old = cache->conf_meta->cache_mode;
	ocf_req_cache_mode_t req_mode = ocf_cache_mode_to_req_cache_mode(mode);
	ocf_req_cache_mode_t req_mode_old =
			ocf_cache_mode_to_req_cache_mode(mode_old);

	/* Check if IO interface type is valid */
	if (!ocf_cache_mode_is_valid(mode))
		return -OCF_ERR_INVAL;

	if (mode == mode_old) {
		ocf_cache_log(cache, log_info, "Cache mode '%s' is already set\n",
				ocf_get_io_iface_name(req_mode));
		return 0;
	}

	cache->conf_meta->cache_mode = mode;

	if (ocf_mngt_cache_mode_has_lazy_write(mode_old) &&
			!ocf_mngt_cache_mode_has_lazy_write(mode)) {
		_cache_mngt_update_initial_dirty_clines(cache);
	}

	ocf_cache_log(cache, log_info, "Changing cache mode from '%s' to '%s' "
			"successful\n", ocf_get_io_iface_name(req_mode_old),
			ocf_get_io_iface_name(req_mode));

	return 0;
}

int ocf_mngt_cache_set_mode(ocf_cache_t cache, ocf_cache_mode_t mode)
{
	ocf_req_cache_mode_t req_mode = ocf_cache_mode_to_req_cache_mode(mode);
	int result;

	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		result = -OCF_ERR_CACHE_DETACHED;

	if (!ocf_cache_mode_is_valid(mode)) {
		ocf_cache_log(cache, log_err, "Cache mode %u is invalid\n",
				mode);
		return -OCF_ERR_INVAL;
	}

	result = _cache_mngt_set_cache_mode(cache, mode);

	if (result) {
		const char *name = ocf_get_io_iface_name(req_mode);

		ocf_cache_log(cache, log_err, "Setting cache mode '%s' "
				"failed\n", name);
	}

	return result;
}

int ocf_mngt_cache_promotion_set_policy(ocf_cache_t cache, ocf_promotion_t type)
{
	int result;

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		return -OCF_ERR_CACHE_DETACHED;

	ocf_metadata_start_exclusive_access(&cache->metadata.lock);

	result = ocf_promotion_set_policy(cache->promotion_policy, type);

	ocf_metadata_end_exclusive_access(&cache->metadata.lock);

	return result;
}

int ocf_mngt_cache_promotion_get_policy(ocf_cache_t cache, ocf_promotion_t *type)
{
	OCF_CHECK_NULL(type);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	ocf_metadata_start_shared_access(&cache->metadata.lock, 0);

	*type = cache->conf_meta->promotion_policy_type;

	ocf_metadata_end_shared_access(&cache->metadata.lock, 0);

	return 0;
}

int ocf_mngt_cache_promotion_get_param(ocf_cache_t cache, ocf_promotion_t type,
		uint8_t param_id, uint32_t *param_value)
{
	int result;

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	ocf_metadata_start_shared_access(&cache->metadata.lock, 0);

	result = ocf_promotion_get_param(cache, type, param_id, param_value);

	ocf_metadata_end_shared_access(&cache->metadata.lock, 0);

	return result;
}

int ocf_mngt_cache_promotion_set_param(ocf_cache_t cache, ocf_promotion_t type,
		uint8_t param_id, uint32_t param_value)
{
	int result;

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		return -OCF_ERR_CACHE_DETACHED;

	ocf_metadata_start_exclusive_access(&cache->metadata.lock);

	result = ocf_promotion_set_param(cache, type, param_id, param_value);

	ocf_metadata_end_exclusive_access(&cache->metadata.lock);

	return result;
}

int ocf_mngt_cache_reset_fallback_pt_error_counter(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (ocf_fallback_pt_is_on(cache)) {
		ocf_cache_log(cache, log_info,
				"Fallback Pass Through inactive\n");
	}

	env_atomic_set(&cache->fallback_pt_error_counter, 0);

	return 0;
}

int ocf_mngt_cache_set_fallback_pt_error_threshold(ocf_cache_t cache,
		uint32_t new_threshold)
{
	bool old_fallback_pt_state, new_fallback_pt_state;

	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (new_threshold > OCF_CACHE_FALLBACK_PT_MAX_ERROR_THRESHOLD)
		return -OCF_ERR_INVAL;

	old_fallback_pt_state = ocf_fallback_pt_is_on(cache);

	cache->fallback_pt_error_threshold = new_threshold;

	new_fallback_pt_state = ocf_fallback_pt_is_on(cache);

	if (old_fallback_pt_state != new_fallback_pt_state) {
		if (new_fallback_pt_state) {
			ocf_cache_log(cache, log_info, "Error threshold reached. "
					"Fallback Pass Through activated\n");
		} else {
			ocf_cache_log(cache, log_info, "Fallback Pass Through "
					"inactive\n");
		}
	}

	return 0;
}

int ocf_mngt_cache_get_fallback_pt_error_threshold(ocf_cache_t cache,
		uint32_t *threshold)
{
	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(threshold);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	*threshold = cache->fallback_pt_error_threshold;

	return 0;
}

static void ocf_mngt_cache_detach_flush_cmpl(ocf_cache_t cache,
		void *priv, int error)
{
	struct ocf_mngt_cache_unplug_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static void ocf_mngt_cache_detach_flush(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_mngt_cache_flush(cache, ocf_mngt_cache_detach_flush_cmpl, context);
}

static void ocf_mngt_cache_detach_stop_cache_io(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	struct env_refcnt *refcnt = &context->cache->refcnt.metadata;

	env_refcnt_freeze(refcnt);
	ocf_mngt_continue_pipeline_on_zero_refcnt(refcnt, context->pipeline);
}

static void ocf_mngt_cache_detach_stop_cleaner_io_finish(void *priv)
{
	ocf_pipeline_t pipeline = priv;
	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_detach_stop_cleaner_io(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_cleaner_refcnt_freeze(cache);
	ocf_cleaner_refcnt_register_zero_cb(cache, &context->cleaner_wait,
			ocf_mngt_cache_detach_stop_cleaner_io_finish,
			pipeline);
}

static void ocf_mngt_cache_detach_remove_cores(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core;
	ocf_core_id_t core_id;
	int no = cache->conf_meta->core_count;

	/* remove cacheline metadata and cleaning policy meta for all cores */
	for_each_core_metadata(cache, core, core_id) {
		cache_mngt_core_deinit_attached_meta(core);
		if (--no == 0)
			break;
	}

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_detach_deinit_services(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ENV_BUG_ON(cache->conf_meta->dirty_flushed == DIRTY_NOT_FLUSHED);

	_ocf_mngt_cache_deinit_services(cache);

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_detach_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	env_refcnt_unfreeze(&cache->refcnt.dirty);

	if (!error) {
		if (!context->cache_write_error) {
			ocf_cache_log(cache, log_info,
				"Device successfully detached\n");
		} else {
			ocf_cache_log(cache, log_warn,
				"Device detached with errors\n");
		}

		_ocf_mngt_cache_set_detached(cache);

		ocf_pipeline_destroy(cache->stop_pipeline);
		cache->stop_pipeline = NULL;
	} else {
		ocf_cache_log(cache, log_err,
				"Detaching device failed\n");
	}

	context->cmpl(cache, context->priv,
			error ?: context->cache_write_error);

	ocf_pipeline_destroy(context->pipeline);
}

struct ocf_pipeline_properties ocf_mngt_cache_detach_pipeline_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_unplug_context),
	.finish = ocf_mngt_cache_detach_finish,
	.steps = {
		OCF_PL_STEP(ocf_mngt_cache_detach_flush),
		OCF_PL_STEP(ocf_mngt_cache_detach_stop_cache_io),
		OCF_PL_STEP(ocf_mngt_cache_detach_stop_cleaner_io),
		OCF_PL_STEP(ocf_mngt_cache_stop_check_dirty),
		OCF_PL_STEP(ocf_mngt_cache_detach_deinit_services),
		OCF_PL_STEP(ocf_mngt_cache_detach_remove_cores),
		OCF_PL_STEP(_ocf_mngt_detach_zero_superblock),
		OCF_PL_STEP(ocf_mngt_cache_close_cache_volume),
		OCF_PL_STEP(ocf_mngt_cache_deinit_metadata),
		OCF_PL_STEP(ocf_mngt_cache_deinit_cache_volume),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_cache_detach(ocf_cache_t cache,
		ocf_mngt_cache_detach_end_t cmpl, void *priv)
{
	struct ocf_mngt_cache_unplug_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_STANDBY);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	if (!ocf_cache_is_device_attached(cache))
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_mngt_cache_detach_pipeline_properties);
	if (result)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_NO_MEM);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	/* prevent dirty io */
	env_refcnt_freeze(&cache->refcnt.dirty);

	ocf_pipeline_next(pipeline);
}
