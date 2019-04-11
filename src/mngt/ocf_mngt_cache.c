/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_mngt_common.h"
#include "ocf_mngt_core_priv.h"
#include "../ocf_priv.h"
#include "../ocf_core_priv.h"
#include "../ocf_queue_priv.h"
#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../utils/utils_part.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_device.h"
#include "../utils/utils_io.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_pipeline.h"
#include "../utils/utils_refcnt.h"
#include "../ocf_utils.h"
#include "../concurrency/ocf_concurrency.h"
#include "../eviction/ops.h"
#include "../ocf_ctx_priv.h"
#include "../cleaning/cleaning.h"

#define OCF_ASSERT_PLUGGED(cache) ENV_BUG_ON(!(cache)->device)

static ocf_cache_t _ocf_mngt_get_cache(ocf_ctx_t owner,
		ocf_cache_id_t cache_id)
{
	ocf_cache_t iter = NULL;
	ocf_cache_t cache = NULL;

	list_for_each_entry(iter, &owner->caches, list) {
		if (iter->cache_id == cache_id) {
			cache = iter;
			break;
		}
	}

	return cache;
}

#define DIRTY_SHUTDOWN_ERROR_MSG "Please use --load option to restore " \
	"previous cache state (Warning: data corruption may happen)"  \
	"\nOr initialize your cache using --force option. " \
	"Warning: All dirty data will be lost!\n"

#define DIRTY_NOT_FLUSHED_ERROR_MSG "Cache closed w/ no data flushing\n" \
	"Restart with --load or --force option\n"

/**
 * @brief Helpful function to start cache
 */
struct ocf_cachemng_init_params {
	bool metadata_volatile;

	ocf_cache_id_t id;
		/*!< cache id */

	ocf_ctx_t ctx;
		/*!< OCF context */

	ocf_cache_t cache;
		/*!< cache that is being initialized */

	uint8_t locked;
		/*!< Keep cache locked */

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

		ocf_metadata_layout_t layout;
		/*!< Metadata layout (striping/sequential) */

		ocf_cache_mode_t cache_mode;
		/*!< cache mode */
	} metadata;
};

typedef void (*_ocf_mngt_cache_attach_end_t)(ocf_cache_t, void *priv1,
	void *priv2, int error);

struct ocf_cache_attach_context {
	ocf_cache_t cache;
		/*!< cache that is being initialized */

	struct ocf_mngt_cache_device_config cfg;

	uint64_t volume_size;
		/*!< size of the device in cache lines */

	enum ocf_mngt_cache_init_mode init_mode;
		/*!< cache init mode */

	/**
	 * @brief initialization state (in case of error, it is used to know
	 * which assets have to be deallocated in premature exit from function
	 */
	struct {
		bool device_alloc : 1;
			/*!< data structure allocated */

		bool volume_inited : 1;
			/*!< uuid for cache device is allocated */

		bool attached_metadata_inited : 1;
			/*!< attached metadata sections initialized */

		bool device_opened : 1;
			/*!< underlying device volume is open */

		bool cleaner_started : 1;
			/*!< Cleaner has been started */

		bool cores_opened : 1;
			/*!< underlying cores are opened (happens only during
			 * load or recovery
			 */

		bool concurrency_inited : 1;
	} flags;

	struct {
		ocf_cache_line_size_t line_size;
		/*!< Metadata cache line size */

		ocf_metadata_layout_t layout;
		/*!< Metadata layout (striping/sequential) */

		ocf_cache_mode_t cache_mode;
		/*!< cache mode */

		enum ocf_metadata_shutdown_status shutdown_status;
		/*!< dirty or clean */

		uint8_t dirty_flushed;
		/*!< is dirty data fully flushed */

		int status;
		/*!< metadata retrieval status (nonzero is sign of an error
		 * during recovery/load but is non issue in case of clean init
		 */
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

static ocf_cache_id_t _ocf_mngt_cache_find_free_id(ocf_ctx_t owner)
{
	ocf_cache_id_t id = OCF_CACHE_ID_INVALID;

	for (id = OCF_CACHE_ID_MIN; id <= OCF_CACHE_ID_MAX; id++) {
		if (!_ocf_mngt_get_cache(owner, id))
			return id;
	}

	return OCF_CACHE_ID_INVALID;
}

static void __init_hash_table(ocf_cache_t cache)
{
	/* Initialize hash table*/
	ocf_metadata_init_hash_table(cache);
}

static void __init_freelist(ocf_cache_t cache)
{
	/* Initialize free list partition*/
	ocf_metadata_init_freelist_partition(cache);
}

static void __init_partitions(ocf_cache_t cache)
{
	ocf_part_id_t i_part;

	/* Init default Partition */
	ENV_BUG_ON(ocf_mngt_add_partition_to_cache(cache, PARTITION_DEFAULT,
			"unclassified", 0, PARTITION_SIZE_MAX,
			OCF_IO_CLASS_PRIO_LOWEST, true));

	/* Add other partition to the cache and make it as dummy */
	for (i_part = 0; i_part < OCF_IO_CLASS_MAX; i_part++) {
		if (i_part == PARTITION_DEFAULT)
			continue;

		/* Init default Partition */
		ENV_BUG_ON(ocf_mngt_add_partition_to_cache(cache, i_part,
				"Inactive", 0, PARTITION_SIZE_MAX,
				OCF_IO_CLASS_PRIO_LOWEST, false));
	}
}

static void __init_partitions_attached(ocf_cache_t cache)
{
	ocf_part_id_t part_id;

	for (part_id = 0; part_id < OCF_IO_CLASS_MAX; part_id++) {
		cache->user_parts[part_id].runtime->head =
				cache->device->collision_table_entries;
		cache->user_parts[part_id].runtime->curr_size = 0;

		ocf_eviction_initialize(cache, part_id);
	}
}

static void __init_cleaning_policy(ocf_cache_t cache)
{
	ocf_cleaning_t cleaning_policy = ocf_cleaning_default;
	int i;

	OCF_ASSERT_PLUGGED(cache);

	for (i = 0; i < ocf_cleaning_max; i++) {
		if (cleaning_policy_ops[i].setup)
			cleaning_policy_ops[i].setup(cache);
	}

	cache->conf_meta->cleaning_policy_type = ocf_cleaning_default;
	if (cleaning_policy_ops[cleaning_policy].initialize)
		cleaning_policy_ops[cleaning_policy].initialize(cache, 1);
}

static void __deinit_cleaning_policy(ocf_cache_t cache)
{
	ocf_cleaning_t cleaning_policy;

	cleaning_policy = cache->conf_meta->cleaning_policy_type;
	if (cleaning_policy_ops[cleaning_policy].deinitialize)
		cleaning_policy_ops[cleaning_policy].deinitialize(cache);
}

static void __init_eviction_policy(ocf_cache_t cache,
		ocf_eviction_t eviction)
{
	ENV_BUG_ON(eviction < 0 || eviction >= ocf_eviction_max);

	cache->conf_meta->eviction_policy_type = eviction;
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

static void __reset_stats(ocf_cache_t cache)
{
	int core_id;
	ocf_part_id_t i;

	for (core_id = 0; core_id < OCF_CORE_MAX; core_id++) {
		env_atomic_set(&cache->core_runtime_meta[core_id].
				cached_clines, 0);
		env_atomic_set(&cache->core_runtime_meta[core_id].
				dirty_clines, 0);
		env_atomic64_set(&cache->core_runtime_meta[core_id].
				dirty_since, 0);

		for (i = 0; i != OCF_IO_CLASS_MAX; i++) {
			env_atomic_set(&cache->core_runtime_meta[core_id].
					part_counters[i].cached_clines, 0);
			env_atomic_set(&cache->core_runtime_meta[core_id].
					part_counters[i].dirty_clines, 0);
		}
	}
}

static void init_attached_data_structures(ocf_cache_t cache,
		ocf_eviction_t eviction_policy)
{
	/* Lock to ensure consistency */
	OCF_METADATA_LOCK_WR();
	__init_hash_table(cache);
	__init_freelist(cache);
	__init_partitions_attached(cache);
	__init_cleaning_policy(cache);
	__init_eviction_policy(cache, eviction_policy);
	OCF_METADATA_UNLOCK_WR();
}

static void init_attached_data_structures_recovery(ocf_cache_t cache)
{
	OCF_METADATA_LOCK_WR();
	__init_hash_table(cache);
	__init_freelist(cache);
	__init_partitions_attached(cache);
	__reset_stats(cache);
	__init_metadata_version(cache);
	OCF_METADATA_UNLOCK_WR();
}

/****************************************************************
 * Function for removing all uninitialized core objects		*
 * from the cache instance.					*
 * Used in case of cache initialization errors.			*
 ****************************************************************/
static void _ocf_mngt_close_all_uninitialized_cores(
		ocf_cache_t cache)
{
	ocf_volume_t volume;
	int j, i;

	for (j = cache->conf_meta->core_count, i = 0; j > 0; ++i) {
		if (!env_bit_test(i, cache->conf_meta->valid_core_bitmap))
			continue;

		volume = &(cache->core[i].volume);
		ocf_volume_close(volume);

		--j;

		env_free(cache->core[i].counters);
		cache->core[i].counters = NULL;

		env_bit_clear(i, cache->conf_meta->valid_core_bitmap);
	}

	cache->conf_meta->core_count = 0;
}

/**
 * @brief routine loading metadata from cache device
 *  - attempts to open all the underlying cores
 */
static int _ocf_mngt_init_instance_add_cores(
		struct ocf_cache_attach_context *context)
{
	ocf_cache_t cache = context->cache;
	/* FIXME: This is temporary hack. Remove after storing name it meta. */
	char core_name[OCF_CORE_NAME_SIZE];
	int ret = -1, i;
	uint64_t hd_lines = 0;

	OCF_ASSERT_PLUGGED(cache);

	if (cache->conf_meta->cachelines !=
	    ocf_metadata_get_cachelines_count(cache)) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cache device size mismatch!\n");
		return -OCF_ERR_START_CACHE_FAIL;
	}

	/* Count value will be re-calculated on the basis of 'added' flag */
	cache->conf_meta->core_count = 0;

	/* Check in metadata which cores were added into cache */
	for (i = 0; i < OCF_CORE_MAX; i++) {
		ocf_volume_t tvolume = NULL;
		ocf_core_t core = &cache->core[i];

		if (!cache->core_conf_meta[i].added)
			continue;

		if (!cache->core[i].volume.type)
			goto err;

		ret = snprintf(core_name, sizeof(core_name), "core%d", i);
		if (ret < 0 || ret >= sizeof(core_name))
			goto err;

		ret = ocf_core_set_name(core, core_name, sizeof(core_name));
		if (ret)
			goto err;

		tvolume = ocf_mngt_core_pool_lookup(ocf_cache_get_ctx(cache),
				&core->volume.uuid, core->volume.type);
		if (tvolume) {
			/*
			 * Attach bottom device to core structure
			 * in cache
			 */
			ocf_volume_move(&core->volume, tvolume);
			ocf_mngt_core_pool_remove(cache->owner, tvolume);

			core->opened = true;
			ocf_cache_log(cache, log_info,
					"Attached core %u from pool\n", i);
		} else {
			ret = ocf_volume_open(&core->volume, NULL);
			if (ret == -OCF_ERR_NOT_OPEN_EXC) {
				ocf_cache_log(cache, log_warn,
						"Cannot open core %u. "
						"Cache is busy", i);
			} else if (ret) {
				ocf_cache_log(cache, log_warn,
						"Cannot open core %u", i);
			} else {
				core->opened = true;
			}
		}

		env_bit_set(i, cache->conf_meta->valid_core_bitmap);
		cache->conf_meta->core_count++;
		core->volume.cache = cache;

		if (ocf_mngt_core_init_front_volume(core))
			goto err;

		core->counters =
			env_zalloc(sizeof(*core->counters), ENV_MEM_NORMAL);
		if (!core->counters)
			goto err;

		if (!core->opened) {
			env_bit_set(ocf_cache_state_incomplete,
					&cache->cache_state);
			cache->ocf_core_inactive_count++;
			ocf_cache_log(cache, log_warn,
					"Cannot find core %u in pool"
					", core added as inactive\n", i);
			continue;
		}

		hd_lines = ocf_bytes_2_lines(cache,
				ocf_volume_get_length(
				&cache->core[i].volume));

		if (hd_lines) {
			ocf_cache_log(cache, log_info,
				"Disk lines = %" ENV_PRIu64 "\n", hd_lines);
		}
	}

	context->flags.cores_opened = true;
	return 0;

err:
	_ocf_mngt_close_all_uninitialized_cores(cache);

	return -OCF_ERR_START_CACHE_FAIL;
}

void _ocf_mngt_init_instance_load_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_cleaning_t cleaning_policy;

	if (error) {
		ocf_cache_log(cache, log_err,
				"Cannot read cache metadata\n");
		ocf_pipeline_finish(context->pipeline,
				-OCF_ERR_START_CACHE_FAIL);
		return;
	}

	cleaning_policy = cache->conf_meta->cleaning_policy_type;
	if (!cleaning_policy_ops[cleaning_policy].initialize)
		goto out;

	if (context->metadata.shutdown_status == ocf_metadata_clean_shutdown)
		cleaning_policy_ops[cleaning_policy].initialize(cache, 0);
	else
		cleaning_policy_ops[cleaning_policy].initialize(cache, 1);

out:
	ocf_pipeline_next(context->pipeline);
}

/**
 * handle load variant
 */
static void _ocf_mngt_init_instance_clean_load(
		struct ocf_cache_attach_context *context)
{
	ocf_cache_t cache = context->cache;

	ocf_metadata_load_all(cache,
			_ocf_mngt_init_instance_load_complete, context);
}

/**
 * handle recovery variant
 */
static void _ocf_mngt_init_instance_recovery(
		struct ocf_cache_attach_context *context)
{
	ocf_cache_t cache = context->cache;

	init_attached_data_structures_recovery(cache);

	ocf_cache_log(cache, log_warn,
			"ERROR: Cache device did not shut down properly!\n");

	ocf_cache_log(cache, log_info, "Initiating recovery sequence...\n");

	ocf_metadata_load_recovery(cache,
			_ocf_mngt_init_instance_load_complete, context);
}

static void _ocf_mngt_init_instance_load(
		struct ocf_cache_attach_context *context)
{
	ocf_cache_t cache = context->cache;
	int ret;

	OCF_ASSERT_PLUGGED(cache);

	ret = _ocf_mngt_init_instance_add_cores(context);
	if (ret) {
		ocf_pipeline_finish(context->pipeline, ret);
		return;
	}

	if (context->metadata.shutdown_status == ocf_metadata_clean_shutdown)
		_ocf_mngt_init_instance_clean_load(context);
	else
		_ocf_mngt_init_instance_recovery(context);
}

/**
 * @brief allocate memory for new cache, add it to cache queue, set initial
 * values and running state
 */
static int _ocf_mngt_init_new_cache(struct ocf_cachemng_init_params *params)
{
	ocf_cache_t cache = env_vzalloc(sizeof(*cache));

	if (!cache)
		return -OCF_ERR_NO_MEM;

	if (env_rwsem_init(&cache->lock) ||
			env_mutex_init(&cache->flush_mutex)) {
		env_vfree(cache);
		return -OCF_ERR_NO_MEM;
	}

	INIT_LIST_HEAD(&cache->list);
	list_add_tail(&cache->list, &params->ctx->caches);
	env_atomic_set(&cache->ref_count, 1);
	cache->owner = params->ctx;

	/* Copy all required initialization parameters */
	cache->cache_id = params->id;

	env_atomic_set(&(cache->last_access_ms),
			env_ticks_to_msecs(env_get_tick_count()));

	env_bit_set(ocf_cache_state_initializing, &cache->cache_state);

	params->cache = cache;
	params->flags.cache_alloc = true;

	return 0;
}

static void _ocf_mngt_attach_cache_device(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_volume_type_t type;
	int ret;

	cache->device = env_vzalloc(sizeof(*cache->device));
	if (!cache->device) {
		ret = -OCF_ERR_NO_MEM;
		goto err;
	}
	context->flags.device_alloc = true;

	cache->device->init_mode = context->init_mode;

	/* Prepare UUID of cache volume */
	type = ocf_ctx_get_volume_type(cache->owner, context->cfg.volume_type);
	if (!type) {
		ret = -OCF_ERR_INVAL_VOLUME_TYPE;
		goto err;
	}

	ret = ocf_volume_init(&cache->device->volume, type,
			&context->cfg.uuid, true);
	if (ret)
		goto err;

	cache->device->volume.cache = cache;
	context->flags.volume_inited = true;

	/*
	 * Open cache device, It has to be done first because metadata service
	 * need to know size of cache device.
	 */
	ret = ocf_volume_open(&cache->device->volume,
			context->cfg.volume_params);
	if (ret) {
		ocf_cache_log(cache, log_err, "ERROR: Cache not available\n");
		goto err;
	}
	context->flags.device_opened = true;

	context->volume_size = ocf_volume_get_length(&cache->device->volume);

	/* Check minimum size of cache device */
	if (context->volume_size < OCF_CACHE_SIZE_MIN) {
		ocf_cache_log(cache, log_err, "ERROR: Cache cache size must "
			"be at least %llu [MiB]\n", OCF_CACHE_SIZE_MIN / MiB);
		ret = -OCF_ERR_START_CACHE_FAIL;
		goto err;
	}

	ocf_pipeline_next(pipeline);
	return;

err:
	ocf_pipeline_finish(context->pipeline, ret);
}

/**
 * @brief prepare cache for init. This is first step towards initializing
 *		the cache
 */
static int _ocf_mngt_init_prepare_cache(struct ocf_cachemng_init_params *param,
		struct ocf_mngt_cache_config *cfg)
{
	ocf_cache_t cache;
	char cache_name[OCF_CACHE_NAME_SIZE];
	int ret = 0;

	ret = env_mutex_lock_interruptible(&param->ctx->lock);
	if (ret)
		return ret;

	if (param->id == OCF_CACHE_ID_INVALID) {
		/* ID was not specified, take first free id */
		param->id = _ocf_mngt_cache_find_free_id(param->ctx);
		if (param->id == OCF_CACHE_ID_INVALID) {
			ret = -OCF_ERR_TOO_MANY_CACHES;
			goto out;
		}
		cfg->id = param->id;
	} else {
		/* ID was set, check if cache exist with specified ID */
		cache = _ocf_mngt_get_cache(param->ctx, param->id);
		if (cache) {
			/* Cache already exist */
			ret = -OCF_ERR_CACHE_EXIST;
			goto out;
		}
	}

	if (cfg->name) {
		ret = env_strncpy(cache_name, sizeof(cache_name),
				cfg->name, sizeof(cache_name));
		if (ret)
			goto out;
	} else {
		ret = snprintf(cache_name, sizeof(cache_name),
				"cache%hu", param->id);
		if (ret < 0)
			goto out;
	}

	ocf_log(param->ctx, log_info, "Inserting cache %s\n", cache_name);

	ret = _ocf_mngt_init_new_cache(param);
	if (ret)
		goto out;

	cache = param->cache;

	ret = ocf_cache_set_name(cache, cache_name, sizeof(cache_name));
	if (ret)
		goto out;

	cache->backfill.max_queue_size = cfg->backfill.max_queue_size;
	cache->backfill.queue_unblock_size = cfg->backfill.queue_unblock_size;

	env_rwsem_down_write(&cache->lock); /* Lock cache during setup */
	param->flags.cache_locked = true;

	cache->pt_unaligned_io = cfg->pt_unaligned_io;
	cache->use_submit_io_fast = cfg->use_submit_io_fast;

	cache->eviction_policy_init = cfg->eviction_policy;
	cache->metadata.is_volatile = cfg->metadata_volatile;

out:
	env_mutex_unlock(&param->ctx->lock);
	return ret;
}

static void _ocf_mngt_test_volume_initial_write_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	if (error) {
		ocf_pipeline_finish(context->test.pipeline, error);
		return;
	}

	ocf_pipeline_next(context->test.pipeline);
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

	if (error) {
		ocf_pipeline_finish(context->test.pipeline, error);
		return;
	}

	ret = env_memcmp(context->test.rw_buffer, PAGE_SIZE,
			context->test.cmp_buffer, PAGE_SIZE, &diff);
	if (ret) {
		ocf_pipeline_finish(context->test.pipeline, ret);
		return;
	}

	if (diff) {
		/* we read back different data than what we had just
		   written - this is fatal error */
		ocf_pipeline_finish(context->test.pipeline, -EIO);
		return;
	}

	if (!ocf_volume_is_atomic(&cache->device->volume)) {
		/* If not atomic, stop testing here */
		ocf_pipeline_finish(context->test.pipeline, 0);
		return;
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

	if (error) {
		ocf_pipeline_finish(context->test.pipeline, error);
		return;
	}

	ocf_pipeline_next(context->test.pipeline);
}

static void _ocf_mngt_test_volume_discard(
		ocf_pipeline_t test_pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	/*
	 * Submit discard request
	 */

	ocf_submit_volume_discard(&cache->device->volume,
			context->test.reserved_lba_addr, PAGE_SIZE,
			_ocf_mngt_test_volume_discard_complete, context);
}

static void _ocf_mngt_test_volume_second_read_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int ret, diff;

	if (error) {
		ocf_pipeline_finish(context->test.pipeline, error);
		return;
	}

	ret = env_memcmp(context->test.rw_buffer, PAGE_SIZE,
			context->test.cmp_buffer, PAGE_SIZE, &diff);
	if (ret) {
		ocf_pipeline_finish(context->test.pipeline, ret);
		return;
	}

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

	if (error)
		ocf_pipeline_finish(context->pipeline, error);
	else
		ocf_pipeline_next(context->pipeline);

	ocf_pipeline_destroy(context->test.pipeline);
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
	ocf_cache_t cache = context->cache;
	ocf_pipeline_t test_pipeline;
	int result;

	cache->device->volume.features.discard_zeroes = 1;

	if (!context->cfg.perform_test) {
		ocf_pipeline_next(pipeline);
		return;
	}

	context->test.reserved_lba_addr = ocf_metadata_get_reserved_lba(cache);

	context->test.rw_buffer = env_malloc(PAGE_SIZE, ENV_MEM_NORMAL);
	if (!context->test.rw_buffer) {
		ocf_pipeline_finish(context->pipeline, -OCF_ERR_NO_MEM);
		return;
	}

	context->test.cmp_buffer = env_malloc(PAGE_SIZE, ENV_MEM_NORMAL);
	if (!context->test.cmp_buffer)
		goto err_buffer;

	result = ocf_pipeline_create(&test_pipeline, cache,
			&_ocf_mngt_test_volume_pipeline_properties);
	if (result)
		goto err_pipeline;

	ocf_pipeline_set_priv(test_pipeline, context);

	context->test.pipeline = test_pipeline;

	ocf_pipeline_next(test_pipeline);
	return;

err_pipeline:
	env_free(context->test.rw_buffer);
err_buffer:
	env_free(context->test.cmp_buffer);
	ocf_pipeline_finish(context->pipeline, -OCF_ERR_NO_MEM);
}

/**
 * Prepare metadata accordingly to mode (for load/recovery read from disk)
 */

static void _ocf_mngt_attach_load_properties_end(void *priv, int error,
		struct ocf_metadata_load_properties *properties)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	context->metadata.status = error;

	if (error) {
		ocf_pipeline_next(context->pipeline);
		return;
	}

	context->metadata.shutdown_status = properties->shutdown_status;
	context->metadata.dirty_flushed = properties->dirty_flushed;

	if (cache->device->init_mode == ocf_init_mode_load) {
		context->metadata.line_size = properties->line_size;
		cache->conf_meta->metadata_layout = properties->layout;
		cache->conf_meta->cache_mode = properties->cache_mode;
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_attach_load_properties(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	OCF_ASSERT_PLUGGED(cache);

	context->metadata.shutdown_status = ocf_metadata_clean_shutdown;
	context->metadata.dirty_flushed = DIRTY_FLUSHED;
	context->metadata.line_size = context->cfg.cache_line_size;

	if (cache->device->init_mode == ocf_init_mode_metadata_volatile) {
		ocf_pipeline_next(context->pipeline);
		return;
	}

	ocf_metadata_load_properties(&cache->device->volume,
			_ocf_mngt_attach_load_properties_end, context);
}

static void _ocf_mngt_attach_prepare_metadata(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int ret, i;

	if (context->init_mode == ocf_init_mode_load &&
			context->metadata.status) {
		ocf_pipeline_finish(context->pipeline,
				-OCF_ERR_START_CACHE_FAIL);
		return;
	}

	context->metadata.line_size = context->metadata.line_size ?:
			cache->metadata.settings.size;

	/*
	 * Initialize variable size metadata segments
	 */
	if (ocf_metadata_init_variable_size(cache, context->volume_size,
			context->metadata.line_size,
			cache->conf_meta->metadata_layout)) {
		ocf_pipeline_finish(context->pipeline,
				-OCF_ERR_START_CACHE_FAIL);
		return;
	}

	ocf_cache_log(cache, log_debug, "Cache attached\n");
	context->flags.attached_metadata_inited = true;

	for (i = 0; i < OCF_IO_CLASS_MAX + 1; ++i) {
		cache->user_parts[i].runtime =
				&cache->device->runtime_meta->user_parts[i];
	}

	cache->device->freelist_part = &cache->device->runtime_meta->freelist_part;

	ret = ocf_concurrency_init(cache);
	if (ret) {
		ocf_pipeline_finish(context->pipeline, ret);
		return;
	}

	context->flags.concurrency_inited = 1;

	ocf_pipeline_next(context->pipeline);
}

/**
 * @brief initializing cache anew (not loading or recovering)
 */
static void _ocf_mngt_init_instance_init(struct ocf_cache_attach_context *context)
{
	ocf_cache_t cache = context->cache;

	if (!context->metadata.status && !context->cfg.force &&
			context->metadata.shutdown_status !=
					ocf_metadata_detached) {

		if (context->metadata.shutdown_status !=
				ocf_metadata_clean_shutdown) {
			ocf_cache_log(cache, log_err, DIRTY_SHUTDOWN_ERROR_MSG);
			ocf_pipeline_finish(context->pipeline,
					-OCF_ERR_DIRTY_SHUTDOWN);
			return;
		}

		if (context->metadata.dirty_flushed == DIRTY_NOT_FLUSHED) {
			ocf_cache_log(cache, log_err,
					DIRTY_NOT_FLUSHED_ERROR_MSG);
			ocf_pipeline_finish(context->pipeline,
					-OCF_ERR_DIRTY_EXISTS);
			return;
		}
	}

	init_attached_data_structures(cache, cache->eviction_policy_init);

	/* In initial cache state there is no dirty data, so all dirty data is
	   considered to be flushed
	 */
	cache->conf_meta->dirty_flushed = true;

	ocf_pipeline_next(context->pipeline);
}

uint64_t _ocf_mngt_calculate_ram_needed(ocf_cache_t cache,
		ocf_volume_t cache_volume)
{
	ocf_cache_line_size_t line_size = ocf_line_size(cache);
	uint64_t volume_size = ocf_volume_get_length(cache_volume);
	uint64_t const_data_size;
	uint64_t cache_line_no;
	uint64_t data_per_line;
	uint64_t min_free_ram;

	/* Superblock + per core metadata */
	const_data_size = 50 * MiB;

	/* Cache metadata */
	cache_line_no = volume_size / line_size;
	data_per_line = (52 + (2 * (line_size / KiB / 4)));

	min_free_ram = const_data_size + cache_line_no * data_per_line;

	/* 110% of calculated value */
	min_free_ram = (11 * min_free_ram) / 10;

	return min_free_ram;
}

int ocf_mngt_get_ram_needed(ocf_cache_t cache,
		struct ocf_mngt_cache_device_config *cfg, uint64_t *ram_needed)
{
	struct ocf_volume volume;
	ocf_volume_type_t type;
	int result;

	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(cfg);
	OCF_CHECK_NULL(ram_needed);

	type = ocf_ctx_get_volume_type(cache->owner, cfg->volume_type);
	if (!type)
		return -OCF_ERR_INVAL_VOLUME_TYPE;

	result = ocf_volume_init(&cache->device->volume, type,
			&cfg->uuid, false);
	if (result)
		return result;

	result = ocf_volume_open(&volume, cfg->volume_params);
	if (result) {
		ocf_volume_deinit(&volume);
		return result;
	}

	*ram_needed = _ocf_mngt_calculate_ram_needed(cache, &volume);

	ocf_volume_close(&volume);
	ocf_volume_deinit(&volume);

	return 0;
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
		struct ocf_cachemng_init_params *params)
{
	ocf_cache_t cache = params->cache;

	if (!params->flags.cache_alloc)
		return;

	if (params->flags.metadata_inited)
		ocf_metadata_deinit(cache);

	env_mutex_lock(&ctx->lock);

	list_del(&cache->list);
	env_vfree(cache);

	env_mutex_unlock(&ctx->lock);
}

static void _ocf_mngt_attach_handle_error(
		struct ocf_cache_attach_context *context)
{
	ocf_cache_t cache = context->cache;

	if (context->flags.cleaner_started)
		ocf_stop_cleaner(cache);

	if (context->flags.cores_opened)
		_ocf_mngt_close_all_uninitialized_cores(cache);

	if (context->flags.attached_metadata_inited)
		ocf_metadata_deinit_variable_size(cache);

	if (context->flags.device_opened)
		ocf_volume_close(&cache->device->volume);

	if (context->flags.concurrency_inited)
		ocf_concurrency_deinit(cache);

	if (context->flags.volume_inited)
		ocf_volume_deinit(&cache->device->volume);

	if (context->flags.device_alloc)
		env_vfree(cache->device);
}

static int _ocf_mngt_cache_init(ocf_cache_t cache,
		struct ocf_cachemng_init_params *params)
{
	int i;

	/*
	 * Super block elements initialization
	 */
	cache->conf_meta->cache_mode = params->metadata.cache_mode;
	cache->conf_meta->metadata_layout = params->metadata.layout;

	for (i = 0; i < OCF_IO_CLASS_MAX + 1; ++i) {
		cache->user_parts[i].config =
				&cache->conf_meta->user_parts[i];
	}

	INIT_LIST_HEAD(&cache->io_queues);

	/* Init Partitions */
	ocf_part_init(cache);

	__init_cores(cache);
	__init_metadata_version(cache);
	__init_partitions(cache);

	return 0;
}

static int _ocf_mngt_cache_start(ocf_ctx_t ctx, ocf_cache_t *cache,
		struct ocf_mngt_cache_config *cfg)
{
	struct ocf_cachemng_init_params params;
	int result;

	ENV_BUG_ON(env_memset(&params, sizeof(params), 0));

	params.id = cfg->id;

	params.ctx = ctx;
	params.metadata.cache_mode = cfg->cache_mode;
	params.metadata.layout = cfg->metadata_layout;
	params.metadata.line_size = cfg->cache_line_size;
	params.metadata_volatile = cfg->metadata_volatile;
	params.locked = cfg->locked;

	/* Prepare cache */
	result = _ocf_mngt_init_prepare_cache(&params, cfg);
	if (result)
		goto _cache_mng_init_instance_ERROR;

	*cache  = params.cache;

	/*
	 * Initialize metadata selected segments of metadata in memory
	 */
	result = ocf_metadata_init(*cache, params.metadata.line_size);
	if (result) {
		result =  -OCF_ERR_START_CACHE_FAIL;
		goto _cache_mng_init_instance_ERROR;
	}

	ocf_log(ctx, log_debug, "Metadata initialized\n");
	params.flags.metadata_inited = true;

	result = _ocf_mngt_cache_init(*cache, &params);
	if (result)
		goto _cache_mng_init_instance_ERROR;

	if (params.locked) {
		/* Increment reference counter to match cache_lock /
		   cache_unlock convention. User is expected to call
		   ocf_mngt_cache_unlock in future which would up the
		   semaphore as well as decrement ref_count. */
		env_atomic_inc(&(*cache)->ref_count);
	} else {
		/* User did not request to lock cache instance after creation -
		   up the semaphore here since we have acquired the lock to
		   perform management operations. */
		env_rwsem_up_write(&(*cache)->lock);
		params.flags.cache_locked = false;
	}

	return 0;

_cache_mng_init_instance_ERROR:
	_ocf_mngt_init_handle_error(ctx, &params);
	*cache = NULL;
	return result;
}

static void _ocf_mng_cache_set_valid(ocf_cache_t cache)
{
	/*
	 * Clear initialization state and set the valid bit so we know
	 * its in use.
	 */
	cache->valid_ocf_cache_device_t = 1;
	env_bit_clear(ocf_cache_state_initializing, &cache->cache_state);
	env_bit_set(ocf_cache_state_running, &cache->cache_state);
}

static int _ocf_mngt_cache_add_cores_t_clean_pol(ocf_cache_t cache)
{
	int clean_type = cache->conf_meta->cleaning_policy_type;
	int i, j, no;
	int result;

	if (cleaning_policy_ops[clean_type].add_core) {
		no = cache->conf_meta->core_count;
		for (i = 0, j = 0; j < no && i < OCF_CORE_MAX; i++) {
			if (!env_bit_test(i, cache->conf_meta->valid_core_bitmap))
				continue;
			result = cleaning_policy_ops[clean_type].add_core(cache, i);
			if (result) {
				goto err;
			}
			j++;
		}
	}

	return 0;

err:
	if (!cleaning_policy_ops[clean_type].remove_core)
		return result;

	while (i--) {
		if (env_bit_test(i, cache->conf_meta->valid_core_bitmap))
			cleaning_policy_ops[clean_type].remove_core(cache, i);
	};

	return result;
}

static void _ocf_mngt_init_attached_nonpersistent(ocf_cache_t cache)
{
	env_atomic_set(&cache->fallback_pt_error_counter, 0);
}

static void _ocf_mngt_attach_check_ram(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	uint64_t min_free_ram;
	uint64_t free_ram;

	min_free_ram = _ocf_mngt_calculate_ram_needed(cache,
			&cache->device->volume);

	free_ram = env_get_free_memory();

	if (free_ram < min_free_ram) {
		ocf_cache_log(cache, log_err, "Not enough free RAM for cache "
				"metadata to start cache\n");
		ocf_cache_log(cache, log_err,
				"Available RAM: %" ENV_PRIu64 " B\n", free_ram);
		ocf_cache_log(cache, log_err, "Needed RAM: %" ENV_PRIu64 " B\n",
				min_free_ram);
		ocf_pipeline_finish(pipeline, -OCF_ERR_NO_FREE_RAM);
	}

	ocf_pipeline_next(pipeline);
}


static void _ocf_mngt_attach_load_superblock_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cannot load cache state\n");
		ocf_pipeline_finish(context->pipeline,
				-OCF_ERR_START_CACHE_FAIL);
		return;
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_attach_load_superblock(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (cache->device->init_mode != ocf_init_mode_load) {
		ocf_pipeline_next(context->pipeline);
		return;
	}

	ocf_cache_log(cache, log_info, "Loading cache state...\n");
	ocf_metadata_load_superblock(cache,
			_ocf_mngt_attach_load_superblock_complete, context);
}

static void _ocf_mngt_attach_init_instance(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	switch (cache->device->init_mode) {
	case ocf_init_mode_init:
	case ocf_init_mode_metadata_volatile:
		_ocf_mngt_init_instance_init(context);
		return;
	case ocf_init_mode_load:
		_ocf_mngt_init_instance_load(context);
		return;
	default:
		ocf_pipeline_finish(context->pipeline, -OCF_ERR_INVAL);
	}
}

static void _ocf_mngt_attach_clean_pol(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	/* TODO: Should this even be here? */
	if (cache->device->init_mode != ocf_init_mode_load) {
		result = _ocf_mngt_cache_add_cores_t_clean_pol(cache);
		if (result) {
			ocf_pipeline_finish(context->pipeline, result);
			return;
		}
	}

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_attach_flush_metadata_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cannot save cache state\n");
		ocf_pipeline_finish(context->pipeline,
				-OCF_ERR_WRITE_CACHE);
		return;
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
			ocf_pipeline_finish(context->pipeline, error);
			return;
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

	if (cache->device->init_mode == ocf_init_mode_load) {
		ocf_pipeline_next(context->pipeline);
		return;
	}

	if (!context->cfg.discard_on_start) {
		ocf_pipeline_next(context->pipeline);
		return;
	}

	if (!discard && ocf_volume_is_atomic(&cache->device->volume)) {
		/* discard doesn't zero data - need to explicitly write zeros */
		ocf_submit_write_zeros(&cache->device->volume, addr, length,
				_ocf_mngt_attach_discard_complete, context);
	} else {
		/* Discard volume after metadata */
		ocf_submit_volume_discard(&cache->device->volume, addr, length,
				_ocf_mngt_attach_discard_complete, context);
	}
}

static void _ocf_mngt_attach_flush_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	if (error)
		ocf_pipeline_finish(context->pipeline, error);
	else
		ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_attach_flush(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	bool discard = cache->device->volume.features.discard_zeroes;

	if (!discard && ocf_volume_is_atomic(&cache->device->volume)) {
		ocf_submit_volume_flush(&cache->device->volume,
				_ocf_mngt_attach_flush_complete, context);
	} else {
		ocf_pipeline_next(context->pipeline);
	}
}

static void _ocf_mngt_attach_shutdown_status_complete(void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err, "Cannot flush shutdown status\n");
		ocf_pipeline_finish(context->pipeline,
				-OCF_ERR_WRITE_CACHE);
		return;
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

static void _ocf_mngt_attach_post_init(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_attach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	if (!context->flags.cleaner_started) {
		result = ocf_start_cleaner(cache);
		if (result) {
			ocf_cache_log(cache, log_err,
					"Error while starting cleaner\n");
			ocf_pipeline_finish(context->pipeline, result);
			return;
		}
		context->flags.cleaner_started = true;
	}

	env_waitqueue_init(&cache->pending_cache_wq);

	env_atomic_set(&cache->attached, 1);

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_cache_attach_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_cache_attach_context *context = priv;

	if (error)
		_ocf_mngt_attach_handle_error(context);

	context->cmpl(context->cache, context->priv1, context->priv2, error);

	env_vfree(context->cfg.uuid.data);
	ocf_pipeline_destroy(context->pipeline);
}

struct ocf_pipeline_properties _ocf_mngt_cache_attach_pipeline_properties = {
	.priv_size = sizeof(struct ocf_cache_attach_context),
	.finish = _ocf_mngt_cache_attach_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_attach_cache_device),
		OCF_PL_STEP(_ocf_mngt_attach_check_ram),
		OCF_PL_STEP(_ocf_mngt_attach_load_properties),
		OCF_PL_STEP(_ocf_mngt_attach_prepare_metadata),
		OCF_PL_STEP(_ocf_mngt_test_volume),
		OCF_PL_STEP(_ocf_mngt_attach_load_superblock),
		OCF_PL_STEP(_ocf_mngt_attach_init_instance),
		OCF_PL_STEP(_ocf_mngt_attach_clean_pol),
		OCF_PL_STEP(_ocf_mngt_attach_flush_metadata),
		OCF_PL_STEP(_ocf_mngt_attach_discard),
		OCF_PL_STEP(_ocf_mngt_attach_flush),
		OCF_PL_STEP(_ocf_mngt_attach_shutdown_status),
		OCF_PL_STEP(_ocf_mngt_attach_post_init),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void _ocf_mngt_cache_attach(ocf_cache_t cache,
		struct ocf_mngt_cache_device_config *cfg, bool load,
		_ocf_mngt_cache_attach_end_t cmpl, void *priv1, void *priv2)
{
	struct ocf_cache_attach_context *context;
	ocf_pipeline_t pipeline;
	void *data;
	int result;

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_cache_attach_pipeline_properties);
	if (result) {
		cmpl(cache, priv1, priv2, -OCF_ERR_NO_MEM);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv1 = priv1;
	context->priv2 = priv2;
	context->pipeline = pipeline;

	context->cache = cache;
	context->cfg = *cfg;

	data = env_vmalloc(cfg->uuid.size);
	if (!data) {
		result = -OCF_ERR_NO_MEM;
		goto err_pipeline;
	}

	result = env_memcpy(data, cfg->uuid.size, cfg->uuid.data,
			cfg->uuid.size);
	if (result)
		goto err_uuid;

	context->cfg.uuid.data = data;

	if (cache->metadata.is_volatile) {
		context->init_mode = ocf_init_mode_metadata_volatile;
	} else {
		context->init_mode = load ?
				ocf_init_mode_load : ocf_init_mode_init;
	}

	_ocf_mngt_init_attached_nonpersistent(cache);

	ocf_pipeline_next(pipeline);
	return;

err_uuid:
	env_vfree(data);
err_pipeline:
	ocf_pipeline_destroy(pipeline);
	cmpl(cache, priv1, priv2, result);
}

static int _ocf_mngt_cache_validate_cfg(struct ocf_mngt_cache_config *cfg)
{
	if (cfg->id > OCF_CACHE_ID_MAX)
		return -OCF_ERR_INVAL;

	if (!ocf_cache_mode_is_valid(cfg->cache_mode))
		return -OCF_ERR_INVALID_CACHE_MODE;

	if (cfg->eviction_policy >= ocf_eviction_max ||
			cfg->eviction_policy < 0) {
		return -OCF_ERR_INVAL;
	}

	if (!ocf_cache_line_size_is_valid(cfg->cache_line_size))
		return -OCF_ERR_INVALID_CACHE_LINE_SIZE;

	if (cfg->metadata_layout >= ocf_metadata_layout_max ||
			cfg->metadata_layout < 0) {
		return -OCF_ERR_INVAL;
	}

	return 0;
}

static int _ocf_mngt_cache_validate_device_cfg(
		struct ocf_mngt_cache_device_config *device_cfg)
{
	if (!device_cfg->uuid.data)
		return -OCF_ERR_INVAL;

	if (device_cfg->uuid.size > OCF_VOLUME_UUID_MAX_SIZE)
		return -OCF_ERR_INVAL;

	if (device_cfg->cache_line_size &&
		!ocf_cache_line_size_is_valid(device_cfg->cache_line_size))
		return -OCF_ERR_INVALID_CACHE_LINE_SIZE;

	return 0;
}

static const char *_ocf_cache_mode_names[ocf_cache_mode_max] = {
	[ocf_cache_mode_wt] = "wt",
	[ocf_cache_mode_wb] = "wb",
	[ocf_cache_mode_wa] = "wa",
	[ocf_cache_mode_pt] = "pt",
	[ocf_cache_mode_wi] = "wi",
};

static const char *_ocf_cache_mode_get_name(ocf_cache_mode_t cache_mode)
{
	if (!ocf_cache_mode_is_valid(cache_mode))
		return NULL;

	return _ocf_cache_mode_names[cache_mode];
}

int ocf_mngt_cache_start(ocf_ctx_t ctx, ocf_cache_t *cache,
		struct ocf_mngt_cache_config *cfg)
{
	int result;

	if (!ctx || !cache || !cfg)
		return -OCF_ERR_INVAL;

	result = _ocf_mngt_cache_validate_cfg(cfg);
	if (result)
		return result;

	result = _ocf_mngt_cache_start(ctx, cache, cfg);
	if (!result) {
		_ocf_mng_cache_set_valid(*cache);

		ocf_cache_log(*cache, log_info, "Successfully added\n");
		ocf_cache_log(*cache, log_info, "Cache mode : %s\n",
			_ocf_cache_mode_get_name(ocf_cache_get_mode(*cache)));
	} else {
		if (cfg->name) {
			ocf_log(ctx, log_err, "Inserting cache %s failed\n",
					cfg->name);
		} else {
			ocf_log(ctx, log_err, "Inserting cache failed\n");
		}
	}

	return result;
}

int ocf_mngt_cache_set_mngt_queue(ocf_cache_t cache, ocf_queue_t queue)
{
	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(queue);

	if (cache->mngt_queue)
		return -OCF_ERR_INVAL;

	ocf_queue_get(queue);
	cache->mngt_queue = queue;

	return 0;
}

static void _ocf_mngt_cache_attach_complete(ocf_cache_t cache, void *priv1,
		void *priv2, int error)
{
	ocf_mngt_cache_attach_end_t cmpl = priv1;

	if (!error) {
		ocf_cache_log(cache, log_info, "Successfully attached\n");
	} else {
		ocf_cache_log(cache, log_err, "Attaching cache device "
			       "failed\n");
	}

	cmpl(cache, priv2, error);
}

void ocf_mngt_cache_attach(ocf_cache_t cache,
		struct ocf_mngt_cache_device_config *cfg,
		ocf_mngt_cache_attach_end_t cmpl, void *priv)
{
	int result;

	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(cfg);

	result = _ocf_mngt_cache_validate_device_cfg(cfg);
	if (result) {
		cmpl(cache, priv, result);
		return;
	}

	_ocf_mngt_cache_attach(cache, cfg, false,
			_ocf_mngt_cache_attach_complete, cmpl, priv);
}

typedef void (*_ocf_mngt_cache_unplug_end_t)(void *context, int error);

struct _ocf_mngt_cache_unplug_context {
	_ocf_mngt_cache_unplug_end_t cmpl;
	void *priv;
	ocf_cache_t cache;
};

static void _ocf_mngt_cache_unplug_complete(void *priv, int error)
{
	struct _ocf_mngt_cache_unplug_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_volume_close(&cache->device->volume);

	ocf_metadata_deinit_variable_size(cache);
	ocf_concurrency_deinit(cache);

	ocf_volume_deinit(&cache->device->volume);

	env_vfree(cache->device);
	cache->device = NULL;
	env_atomic_set(&cache->attached, 0);

	/* TODO: this should be removed from detach after 'attached' stats
		are better separated in statistics */
	_ocf_mngt_init_attached_nonpersistent(cache);

	context->cmpl(context->priv, error ? -OCF_ERR_WRITE_CACHE : 0);
	env_vfree(context);
}

/**
 * @brief Unplug caching device from cache instance. Variable size metadata
 *	  containers are deinitialiazed as well as other cacheline related
 *	  structures. Cache volume is closed.
 *
 * @param cache OCF cache instance
 * @param stop	- true if unplugging during stop - in this case we mark
 *		    clean shutdown in metadata and flush all containers.
 *		- false if the device is to be detached from cache - loading
 *		    metadata from this device will not be possible.
 * @param cmpl Completion callback
 * @param priv Completion context
 */
static void _ocf_mngt_cache_unplug(ocf_cache_t cache, bool stop,
		_ocf_mngt_cache_unplug_end_t cmpl, void *priv)
{
	struct _ocf_mngt_cache_unplug_context *context;

	ENV_BUG_ON(stop && cache->conf_meta->core_count != 0);

	context = env_vzalloc(sizeof(*context));
	if (!context) {
		cmpl(priv, -OCF_ERR_NO_MEM);
		return;
	}

	context->cmpl = cmpl;
	context->priv = priv;
	context->cache = cache;

	ocf_stop_cleaner(cache);

	__deinit_cleaning_policy(cache);

	if (ocf_mngt_cache_is_dirty(cache)) {
		ENV_BUG_ON(!stop);

		cache->conf_meta->dirty_flushed = DIRTY_NOT_FLUSHED;

		ocf_cache_log(cache, log_warn, "Cache is still dirty. "
				"DO NOT USE your core devices until flushing "
				"dirty data!\n");
	} else {
		cache->conf_meta->dirty_flushed = DIRTY_FLUSHED;
	}

	if (!stop) {
		/* Just set correct shutdown status */
		ocf_metadata_set_shutdown_status(cache, ocf_metadata_detached,
				_ocf_mngt_cache_unplug_complete, context);
	} else {
		/* Flush metadata */
		ocf_metadata_flush_all(cache,
				_ocf_mngt_cache_unplug_complete, context);
	}
}

static int _ocf_mngt_cache_load_core_log(ocf_core_t core, void *cntx)
{
	ocf_core_log(core, log_info, "Successfully added\n");

	return 0;
}

static void _ocf_mngt_cache_load_log(ocf_cache_t cache)
{
	ocf_cache_mode_t cache_mode = ocf_cache_get_mode(cache);
	ocf_eviction_t eviction_type = cache->conf_meta->eviction_policy_type;
	ocf_cleaning_t cleaning_type = cache->conf_meta->cleaning_policy_type;

	ocf_cache_log(cache, log_info, "Successfully loaded\n");
	ocf_cache_log(cache, log_info, "Cache mode : %s\n",
			_ocf_cache_mode_get_name(cache_mode));
	ocf_cache_log(cache, log_info, "Eviction policy : %s\n",
			evict_policy_ops[eviction_type].name);
	ocf_cache_log(cache, log_info, "Cleaning policy : %s\n",
			cleaning_policy_ops[cleaning_type].name);
	ocf_core_visit(cache, _ocf_mngt_cache_load_core_log,
			cache, false);
}

static void _ocf_mngt_cache_load_complete(ocf_cache_t cache, void *priv1,
		void *priv2, int error)
{
	ocf_mngt_cache_load_end_t cmpl = priv1;

	if (error) {
		cmpl(cache, priv2, error);
		return;
	}

	_ocf_mng_cache_set_valid(cache);
	_ocf_mngt_cache_load_log(cache);

	cmpl(cache, priv2, 0);
}

void ocf_mngt_cache_load(ocf_cache_t cache,
		struct ocf_mngt_cache_device_config *cfg,
		ocf_mngt_cache_load_end_t cmpl, void *priv)
{
	int result;

	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(cfg);

	/* Load is not allowed in volatile metadata mode */
	if (cache->metadata.is_volatile)
		cmpl(cache, priv, -EINVAL);

	result = _ocf_mngt_cache_validate_device_cfg(cfg);
	if (result) {
		cmpl(cache, priv, result);
		return;
	}

	_ocf_mngt_cache_attach(cache, cfg, true,
			_ocf_mngt_cache_load_complete, cmpl, priv);
}

struct ocf_mngt_cache_stop_context {
	ocf_mngt_cache_stop_end_t cmpl;
	void *priv;
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
	ocf_ctx_t ctx;
	char cache_name[OCF_CACHE_NAME_SIZE];
	int cache_write_error;
};

static void ocf_mngt_cache_stop_wait_io(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_stop_context *context = priv;
	ocf_cache_t cache = context->cache;

	/* TODO: Make this asynchronous! */
	ocf_cache_wait_for_io_finish(cache);
	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_stop_remove_cores(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_stop_context *context = priv;
	ocf_cache_t cache = context->cache;
	int i, j, no;

	no = cache->conf_meta->core_count;

	/* All exported objects removed, cleaning up rest. */
	for (i = 0, j = 0; j < no && i < OCF_CORE_MAX; i++) {
		if (!env_bit_test(i, cache->conf_meta->valid_core_bitmap))
			continue;
		cache_mng_core_remove_from_cache(cache, i);
		if (ocf_cache_is_device_attached(cache))
			cache_mng_core_remove_from_cleaning_pol(cache, i);
		cache_mng_core_close(cache, i);
		j++;
	}
	ENV_BUG_ON(cache->conf_meta->core_count != 0);

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_stop_unplug_complete(void *priv, int error)
{
	struct ocf_mngt_cache_stop_context *context = priv;

	/* short-circut execution in case of critical error */
	if (error && error != -OCF_ERR_WRITE_CACHE) {
		ocf_pipeline_finish(context->pipeline, error);
		return;
	}

	/* in case of non-critical (disk write) error just remember its value */
	if (error)
		context->cache_write_error = error;

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_stop_unplug(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_stop_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (!env_atomic_read(&cache->attached)) {
		ocf_pipeline_next(pipeline);
		return;
	}

	_ocf_mngt_cache_unplug(cache, true,
			ocf_mngt_cache_stop_unplug_complete, context);
}

static void ocf_mngt_cache_stop_put_io_queues(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_stop_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_queue_t queue, tmp_queue;

	list_for_each_entry_safe(queue, tmp_queue, &cache->io_queues, list)
		ocf_queue_put(queue);

	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_stop_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_mngt_cache_stop_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_ctx_t ctx = context->ctx;

	if (!error) {
		env_mutex_lock(&ctx->lock);
		/* Mark device uninitialized */
		cache->valid_ocf_cache_device_t = 0;
		/* Remove cache from the list */
		list_del(&cache->list);
		env_mutex_unlock(&ctx->lock);
	} else {
		env_bit_clear(ocf_cache_state_stopping, &cache->cache_state);
		env_bit_set(ocf_cache_state_running, &cache->cache_state);
	}

	if (context->cache_write_error) {
		ocf_log(ctx, log_warn, "Stopped cache %s with errors\n",
				context->cache_name);
	} else if (error) {
		ocf_log(ctx, log_err, "Stopping cache %s failed\n",
				context->cache_name);
	} else {
		ocf_log(ctx, log_info, "Cache %s successfully stopped\n",
				context->cache_name);
	}

	context->cmpl(cache, context->priv,
			error ?: context->cache_write_error);

	ocf_pipeline_destroy(context->pipeline);

	if (!error) {
		/* Finally release cache instance */
		ocf_mngt_cache_put(cache);
	}
}

struct ocf_pipeline_properties ocf_mngt_cache_stop_pipeline_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_stop_context),
	.finish = ocf_mngt_cache_stop_finish,
	.steps = {
		OCF_PL_STEP(ocf_mngt_cache_stop_wait_io),
		OCF_PL_STEP(ocf_mngt_cache_stop_remove_cores),
		OCF_PL_STEP(ocf_mngt_cache_stop_unplug),
		OCF_PL_STEP(ocf_mngt_cache_stop_put_io_queues),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_cache_stop(ocf_cache_t cache,
		ocf_mngt_cache_stop_end_t cmpl, void *priv)
{
	struct ocf_mngt_cache_stop_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_CHECK_NULL(cache);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_mngt_cache_stop_pipeline_properties);
	if (result) {
		cmpl(cache, priv, -OCF_ERR_NO_MEM);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->ctx = cache->owner;

	result = env_strncpy(context->cache_name, sizeof(context->cache_name),
			ocf_cache_get_name(cache), sizeof(context->cache_name));
	if (result) {
		ocf_pipeline_destroy(pipeline);
		cmpl(cache, priv, -OCF_ERR_NO_MEM);
		return;
	}

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
		ocf_pipeline_finish(context->pipeline, -OCF_ERR_WRITE_CACHE);
		return;
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

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_mngt_cache_save_pipeline_properties);
	if (result) {
		cmpl(cache, priv, result);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	ocf_metadata_flush_superblock(cache,
			ocf_mngt_cache_save_flush_sb_complete, context);
}

static int _cache_mng_set_cache_mode(ocf_cache_t cache, ocf_cache_mode_t mode)
{
	ocf_cache_mode_t mode_old = cache->conf_meta->cache_mode;

	/* Check if IO interface type is valid */
	if (!ocf_cache_mode_is_valid(mode))
		return -OCF_ERR_INVAL;

	if (mode == mode_old) {
		ocf_cache_log(cache, log_info, "Cache mode '%s' is already set\n",
				ocf_get_io_iface_name(mode));
		return 0;
	}

	cache->conf_meta->cache_mode = mode;

	if (ocf_cache_mode_wb == mode_old) {
		int i;

		for (i = 0; i != OCF_CORE_MAX; ++i) {
			if (!env_bit_test(i, cache->conf_meta->valid_core_bitmap))
				continue;
			env_atomic_set(&cache->core_runtime_meta[i].
					initial_dirty_clines,
					env_atomic_read(&cache->
						core_runtime_meta[i].dirty_clines));
		}
	}

	ocf_cache_log(cache, log_info, "Changing cache mode from '%s' to '%s' "
			"successful\n", ocf_get_io_iface_name(mode_old),
			ocf_get_io_iface_name(mode));

	return 0;
}

int ocf_mngt_cache_set_mode(ocf_cache_t cache, ocf_cache_mode_t mode)
{
	int result;

	OCF_CHECK_NULL(cache);

	if (!ocf_cache_mode_is_valid(mode)) {
	        ocf_cache_log(cache, log_err, "Cache mode %u is invalid\n",
				mode);
		return -OCF_ERR_INVAL;
	}

	result = _cache_mng_set_cache_mode(cache, mode);

	if (result) {
		const char *name = ocf_get_io_iface_name(mode);

		ocf_cache_log(cache, log_err, "Setting cache mode '%s' "
				"failed\n", name);
	}

	return result;
}

int ocf_mngt_cache_reset_fallback_pt_error_counter(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

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

	*threshold = cache->fallback_pt_error_threshold;

	return 0;
}

struct ocf_mngt_cache_detach_context {
	ocf_mngt_cache_detach_end_t cmpl;
	void *priv;
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
};

static void ocf_mngt_cache_detach_flush_cmpl(ocf_cache_t cache,
		void *priv, int error)
{
	struct ocf_mngt_cache_detach_context *context = priv;

	if (error) {
		ocf_pipeline_finish(context->pipeline, error);
		return;
	}

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_detach_flush(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_detach_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_mngt_cache_flush(cache, true, ocf_mngt_cache_detach_flush_cmpl,
			context);
}

static void ocf_mngt_cache_detach_wait_pending(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_detach_context *context = priv;
	ocf_cache_t cache = context->cache;

	env_atomic_set(&cache->attached, 0);

	/* FIXME: This should be asynchronous! */
	env_waitqueue_wait(cache->pending_cache_wq,
			!env_atomic_read(&cache->pending_cache_requests));

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_detach_update_metadata(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_detach_context *context = priv;
	ocf_cache_t cache = context->cache;
	int i, j, no;

	no = cache->conf_meta->core_count;

	/* remove cacheline metadata and cleaning policy meta for all cores */
	for (i = 0, j = 0; j < no && i < OCF_CORE_MAX; i++) {
		if (!env_bit_test(i, cache->conf_meta->valid_core_bitmap))
			continue;
		cache_mng_core_deinit_attached_meta(cache, i);
		cache_mng_core_remove_from_cleaning_pol(cache, i);
		j++;
	}

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_detach_unplug_complete(void *priv, int error)
{
	struct ocf_mngt_cache_detach_context *context = priv;

	if (error) {
		ocf_pipeline_finish(context->pipeline, error);
		return;
	}

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_detach_unplug(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_detach_context *context = priv;
	ocf_cache_t cache = context->cache;

	/* Do the actual detach - deinit cacheline metadata,
	 * stop cleaner thread and close cache bottom device */
	_ocf_mngt_cache_unplug(cache, false,
			ocf_mngt_cache_detach_unplug_complete, context);
}

static void ocf_mngt_cache_detach_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_mngt_cache_detach_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_refcnt_unfreeze(&cache->dirty);

	if (!error) {
		ocf_cache_log(cache, log_info, "Successfully detached\n");
	} else {
		if (error == -OCF_ERR_WRITE_CACHE) {
			ocf_cache_log(cache, log_warn,
					"Detached cache with errors\n");
		} else {
			ocf_cache_log(cache, log_err,
					"Detaching cache failed\n");
		}
	}

	context->cmpl(cache, context->priv, error);

	ocf_pipeline_destroy(context->pipeline);
}

struct ocf_pipeline_properties ocf_mngt_cache_detach_pipeline_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_detach_context),
	.finish = ocf_mngt_cache_detach_finish,
	.steps = {
		OCF_PL_STEP(ocf_mngt_cache_detach_flush),
		OCF_PL_STEP(ocf_mngt_cache_detach_wait_pending),
		OCF_PL_STEP(ocf_mngt_cache_detach_update_metadata),
		OCF_PL_STEP(ocf_mngt_cache_detach_unplug),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_cache_detach(ocf_cache_t cache,
		ocf_mngt_cache_detach_end_t cmpl, void *priv)
{
	struct ocf_mngt_cache_detach_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_CHECK_NULL(cache);

	if (!env_atomic_read(&cache->attached)) {
		cmpl(cache, priv, -OCF_ERR_INVAL);
		return;
	}

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_mngt_cache_detach_pipeline_properties);
	if (result) {
		cmpl(cache, priv, -OCF_ERR_NO_MEM);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	/* prevent dirty io */
	ocf_refcnt_freeze(&cache->dirty);

	ocf_pipeline_next(pipeline);
}
