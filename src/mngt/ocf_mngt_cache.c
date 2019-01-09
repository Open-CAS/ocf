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
#include "../ocf_utils.h"
#include "../concurrency/ocf_concurrency.h"
#include "../eviction/ops.h"
#include "../ocf_ctx_priv.h"
#include "../cleaning/cleaning.h"

#define OCF_ASSERT_PLUGGED(cache) ENV_BUG_ON(!(cache)->device)

static struct ocf_cache *_ocf_mngt_get_cache(ocf_ctx_t owner,
		ocf_cache_id_t cache_id)
{
	struct ocf_cache *iter = NULL;
	struct ocf_cache *cache = NULL;

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

	struct ocf_cache *cache;
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

		bool queues_inited : 1;

		bool cache_locked : 1;
			/*!< Cache has been locked */

		bool io_queues_started : 1;
			/*!< queues are started */
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

struct ocf_cachemng_attach_params {
	struct ocf_cache *cache;
		/*!< cache that is being initialized */

	struct ocf_data_obj_uuid uuid;
		/*!< Caching device data object UUID */

	uint8_t device_type;
		/*!< data object (block device) type */

	uint64_t device_size;
		/*!< size of the device in cache lines */

	uint8_t force;
		/*!< if force switch was passed in CLI (if this flag is set,
		 * routine overrides some safety checks, that normally prevent
		 * completion of initialization procedure
		 */

	uint8_t load;
		/*!< 1 if load from attached device is requested */

	bool perform_test;
		/*!< Test cache before starting */

	/**
	 * @brief initialization state (in case of error, it is used to know
	 * which assets have to be deallocated in premature exit from function
	 */
	struct {
		bool device_alloc : 1;
			/*!< data structure allocated */

		bool data_obj_inited : 1;
			/*!< uuid for cache device is allocated */

		bool attached_metadata_inited : 1;
			/*!< attached metadata sections initialized */

		bool device_opened : 1;
			/*!< underlying device object is open */

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

	uint64_t min_free_ram;
		/*!< Minimum free RAM required to start cache. Set during
		 * cache start procedure
		 */
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

static void __init_hash_table(struct ocf_cache *cache)
{
	/* Initialize hash table*/
	ocf_metadata_init_hash_table(cache);
}

static void __init_freelist(struct ocf_cache *cache)
{
	/* Initialize free list partition*/
	ocf_metadata_init_freelist_partition(cache);
}

static void __init_partitions(struct ocf_cache *cache)
{
	ocf_part_id_t i_part;

	/* Init default Partition */
	ENV_BUG_ON(ocf_mngt_add_partition_to_cache(cache, PARTITION_DEFAULT,
			"Unclassified", 0, PARTITION_SIZE_MAX,
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

static void __init_partitions_attached(struct ocf_cache *cache)
{
	ocf_part_id_t part_id;

	for (part_id = 0; part_id < OCF_IO_CLASS_MAX; part_id++) {
		cache->user_parts[part_id].runtime->head =
				cache->device->collision_table_entries;
		cache->user_parts[part_id].runtime->curr_size = 0;

		ocf_eviction_initialize(cache, part_id);
	}
}

static void __init_cleaning_policy(struct ocf_cache *cache)
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

static void __deinit_cleaning_policy(struct ocf_cache *cache)
{
	ocf_cleaning_t cleaning_policy;

	cleaning_policy = cache->conf_meta->cleaning_policy_type;
	if (cleaning_policy_ops[cleaning_policy].deinitialize)
		cleaning_policy_ops[cleaning_policy].deinitialize(cache);
}

static void __init_eviction_policy(struct ocf_cache *cache,
		ocf_eviction_t eviction)
{
	ENV_BUG_ON(eviction < 0 || eviction >= ocf_eviction_max);

	cache->conf_meta->eviction_policy_type = eviction;
}

static void __init_cores(struct ocf_cache *cache)
{
	/* No core devices yet */
	cache->conf_meta->core_count = 0;
	ENV_BUG_ON(env_memset(cache->conf_meta->valid_object_bitmap,
			sizeof(cache->conf_meta->valid_object_bitmap), 0));
}

static void __init_metadata_version(struct ocf_cache *cache)
{
	cache->conf_meta->metadata_version = METADATA_VERSION();
}

static void init_attached_data_structures(struct ocf_cache *cache,
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

static void __reset_stats(struct ocf_cache *cache)
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

static void init_attached_data_structures_recovery(struct ocf_cache *cache)
{
	OCF_METADATA_LOCK_WR();
	__init_hash_table(cache);
	__init_freelist(cache);
	__init_partitions_attached(cache);
	__reset_stats(cache);
	__init_metadata_version(cache);
	OCF_METADATA_UNLOCK_WR();
}

/**
 * @brief initialize partitions for a caching device
 */
static void _init_partitions(ocf_cache_t cache)
{
	int clean_type = cache->conf_meta->cleaning_policy_type;

	if (clean_type >= 0 && clean_type < ocf_cleaning_max) {
		/* Initialize policy with settings restored
		 * from metadata.
		 */
		if (cleaning_policy_ops[clean_type].initialize)
			cleaning_policy_ops[clean_type].initialize(cache, 0);
	} else {
		ocf_cache_log(cache, log_warn,
			"Wrong cleaning policy type=%d\n", clean_type);
	}
}

/****************************************************************
 * Function for removing all uninitialized core objects		*
 * from the cache instance.					*
 * Used in case of cache initialization errors.			*
 ****************************************************************/
static void _ocf_mngt_close_all_uninitialized_cores(
		struct ocf_cache *cache)
{
	ocf_data_obj_t obj;
	int j, i;

	for (j = cache->conf_meta->core_count, i = 0; j > 0; ++i) {
		if (!env_bit_test(i, cache->conf_meta->valid_object_bitmap))
			continue;

		obj = &(cache->core[i].obj);
		ocf_dobj_close(obj);

		--j;

		env_free(cache->core[i].counters);
		cache->core[i].counters = NULL;

		env_bit_clear(i, cache->conf_meta->valid_object_bitmap);
	}

	cache->conf_meta->core_count = 0;
}

/**
 * @brief routine loading metadata from cache device
 *  - attempts to open all the underlying cores
 */
static int _ocf_mngt_init_instance_add_cores(
		struct ocf_cachemng_attach_params *attach_params)
{
	struct ocf_cache *cache = attach_params->cache;
	/* FIXME: This is temporary hack. Remove after storing name it meta. */
	char core_name[OCF_CORE_NAME_SIZE];
	int ret = -1, i;
	uint64_t hd_lines = 0;

	OCF_ASSERT_PLUGGED(cache);

	ocf_cache_log(cache, log_info, "Loading cache state...\n");
	if (ocf_metadata_load_superblock(cache)) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cannot load cache state\n");
		return -OCF_ERR_START_CACHE_FAIL;
	}

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
		ocf_data_obj_t tobj = NULL;
		ocf_core_t core = &cache->core[i];

		if (!cache->core_conf_meta[i].added)
			continue;

		if (!cache->core[i].obj.type)
			goto err;

		ret = snprintf(core_name, sizeof(core_name), "core%d", i);
		if (ret < 0 || ret >= sizeof(core_name))
			goto err;

		ret = ocf_core_set_name(core, core_name, sizeof(core_name));
		if (ret)
			goto err;

		tobj = ocf_mngt_core_pool_lookup(ocf_cache_get_ctx(cache),
				&core->obj.uuid, core->obj.type);
		if (tobj) {
			/*
			 * Attach bottom device to core structure
			 * in cache
			 */
			ocf_dobj_move(&core->obj, tobj);
			ocf_mngt_core_pool_remove(cache->owner, tobj);

			core->opened = true;
			ocf_cache_log(cache, log_info,
					"Attached core %u from pool\n", i);
		} else {
			ret = ocf_dobj_open(&core->obj);
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

		env_bit_set(i, cache->conf_meta->valid_object_bitmap);
		cache->conf_meta->core_count++;
		core->obj.cache = cache;

		if (ocf_mngt_core_init_front_dobj(core))
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
				ocf_dobj_get_length(
				&cache->core[i].obj));

		if (hd_lines) {
			ocf_cache_log(cache, log_info,
				"Disk lines = %" ENV_PRIu64 "\n", hd_lines);
		}
	}

	attach_params->flags.cores_opened = true;
	return 0;

err:
	_ocf_mngt_close_all_uninitialized_cores(cache);

	return -OCF_ERR_START_CACHE_FAIL;
}

/**
 * @brief routine implementing "recovery" feature - flushes dirty data to
 * underlying cores and closes them
 * @param cache caching device that is opened but not fully initialized
 */
static int _recover_cache(struct ocf_cache *cache)
{
	ocf_cache_log(cache, log_warn,
			"ERROR: Cache device did not shut down properly!\n");

	ocf_cache_log(cache, log_info, "Initiating recovery sequence...\n");

	if (ocf_metadata_load_recovery(cache)) {
		ocf_cache_log(cache, log_err,
				"Cannot read metadata for recovery\n");
		return -OCF_ERR_START_CACHE_FAIL;
	}

	return 0;
}

/**
 * handle --start-cache -r variant
 */
static int _ocf_mngt_init_instance_recovery(
		struct ocf_cachemng_attach_params *attach_params)
{
	int result = 0;
	struct ocf_cache *cache = attach_params->cache;
	ocf_cleaning_t cleaning_policy;

	OCF_ASSERT_PLUGGED(cache);

	init_attached_data_structures_recovery(cache);

	result = _recover_cache(cache);
	if (result)
		return result;

	cleaning_policy = cache->conf_meta->cleaning_policy_type;
	if (cleaning_policy_ops[cleaning_policy].initialize) {
		cleaning_policy_ops[cleaning_policy].initialize(cache, 1);
	}

	if (ocf_metadata_flush_all(cache)) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cannot save cache state\n");
		return -OCF_ERR_START_CACHE_FAIL;
	}

	return 0;
}

/**
 * handle --start-cache -l variant
 */
static int _ocf_mngt_init_instance_load(
		struct ocf_cachemng_attach_params *attach_params)
{
	struct ocf_cache *cache = attach_params->cache;
	int ret;

	OCF_ASSERT_PLUGGED(cache);

	ret = _ocf_mngt_init_instance_add_cores(attach_params);
	if (ret)
		return ret;

	if (ocf_metadata_clean_shutdown != attach_params->metadata.shutdown_status) {
		/* When dirty shutdown perform recovery */
		return _ocf_mngt_init_instance_recovery(attach_params);
	}

	ret = ocf_metadata_load_all(cache);
	if (ret) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cannot load cache state\n");
		return -OCF_ERR_START_CACHE_FAIL;
	}

	_init_partitions(cache);

	return ret;
}

/**
 * @brief allocate memory for new cache, add it to cache queue, set initial
 * values and running state
 */
static int _ocf_mngt_init_new_cache(struct ocf_cachemng_init_params *params)
{
	struct ocf_cache *cache = env_vzalloc(sizeof(*cache));

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

static int _ocf_mngt_attach_cache_device(struct ocf_cache *cache,
		struct ocf_cachemng_attach_params *attach_params)
{
	ocf_data_obj_type_t type;
	int ret;

	cache->device = env_vzalloc(sizeof(*cache->device));
	if (!cache->device)
		return -OCF_ERR_NO_MEM;
	attach_params->flags.device_alloc = true;

	cache->device->obj.cache = cache;

	/* Prepare UUID of cache data object */
	type = ocf_ctx_get_data_obj_type(cache->owner,
			attach_params->device_type);
	if (!type) {
		ret = -OCF_ERR_INVAL_DATA_OBJ_TYPE;
		goto err;
	}

	ret = ocf_dobj_init(&cache->device->obj, type,
			&attach_params->uuid, true);
	if (ret)
		goto err;

	attach_params->flags.data_obj_inited = true;

	/*
	 * Open cache device, It has to be done first because metadata service
	 * need to know size of cache device.
	 */
	ret = ocf_dobj_open(&cache->device->obj);
	if (ret) {
		ocf_cache_log(cache, log_err, "ERROR: Cache not available\n");
		goto err;
	}
	attach_params->flags.device_opened = true;

	attach_params->device_size = ocf_dobj_get_length(&cache->device->obj);

	/* Check minimum size of cache device */
	if (attach_params->device_size < OCF_CACHE_SIZE_MIN) {
		ocf_cache_log(cache, log_err, "ERROR: Cache cache size must "
			"be at least %llu [MiB]\n", OCF_CACHE_SIZE_MIN / MiB);
		ret = -OCF_ERR_START_CACHE_FAIL;
		goto err;
	}

	if (cache->metadata.is_volatile) {
		cache->device->init_mode = ocf_init_mode_metadata_volatile;
	} else {
		cache->device->init_mode =  attach_params->load ?
			ocf_init_mode_load : ocf_init_mode_init;
	}

	return 0;

err:
	return ret;
}

/**
 * @brief prepare cache for init. This is first step towards initializing
 *		the cache
 */
static int _ocf_mngt_init_prepare_cache(struct ocf_cachemng_init_params *param,
		struct ocf_mngt_cache_config *cfg)
{
	struct ocf_cache *cache;
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

	cache->io_queues_no = cfg->io_queues;
	cache->pt_unaligned_io = cfg->pt_unaligned_io;
	cache->use_submit_io_fast = cfg->use_submit_io_fast;

	cache->eviction_policy_init = cfg->eviction_policy;
	cache->metadata.is_volatile = cfg->metadata_volatile;

out:
	env_mutex_unlock(&param->ctx->lock);
	return ret;
}


/**
 * @brief read data from given address and compare it against cmp_buffer
 *
 * @param[in] cache OCF cache
 * @param[in] addr target adres for read operation
 * @param[in] rw_buffer buffer to store data read from addr
 * @param[in] cmp_buffer buffer to compare against
 * @param[out] diff buffers diff

 * @return error code in case of error, 0 in case of success
*/
static int __ocf_mngt_init_test_device_submit_and_cmp(struct ocf_cache *cache,
		uint64_t addr, void *rw_buffer, void *cmp_buffer, int *diff)
{
	int ret;

	ret = ocf_submit_cache_page(cache, addr, OCF_READ,
			rw_buffer);
	if (ret)
		goto end;

	ret = env_memcmp(rw_buffer, PAGE_SIZE, cmp_buffer, PAGE_SIZE, diff);

end:
	return ret;
}

static int _ocf_mngt_init_test_device(struct ocf_cache *cache)
{
	unsigned long reserved_lba_addr;
	void *rw_buffer = NULL, *cmp_buffer = NULL;
	int ret;
	int diff;

	rw_buffer = env_malloc(PAGE_SIZE, ENV_MEM_NORMAL);
	if (!rw_buffer) {
		ret = -OCF_ERR_NO_MEM;
		goto end;
	}

	cmp_buffer = env_malloc(PAGE_SIZE, ENV_MEM_NORMAL);
	if (!cmp_buffer) {
		ret = -OCF_ERR_NO_MEM;
		goto end;
	}

	reserved_lba_addr = ocf_metadata_get_reserved_lba(cache);

	/*
	 * Write buffer filled "1"
	 */

	ENV_BUG_ON(env_memset(rw_buffer, PAGE_SIZE, 1));

	ret = ocf_submit_cache_page(cache, reserved_lba_addr,
			OCF_WRITE, rw_buffer);
	if (ret)
		goto end;

	/*
	 * First read
	 */

	ENV_BUG_ON(env_memset(rw_buffer, PAGE_SIZE, 0));
	ENV_BUG_ON(env_memset(cmp_buffer, PAGE_SIZE, 1));

	ret = __ocf_mngt_init_test_device_submit_and_cmp(cache,
			reserved_lba_addr, rw_buffer, cmp_buffer, &diff);
	if (ret)
		goto end;
	if (diff) {
		/* we read back different data than what we had just
		   written - this is fatal error */
		ret = -EIO;
		goto end;
	}

	if (!ocf_dobj_is_atomic(&cache->device->obj))
		goto end;

	/*
	 * Submit discard request
	 */
	ret = ocf_submit_obj_discard_wait(&cache->device->obj,
			reserved_lba_addr, PAGE_SIZE);
	if (ret)
		goto end;

	/*
	 * Second read
	 */

	ENV_BUG_ON(env_memset(rw_buffer, PAGE_SIZE, 1));
	ENV_BUG_ON(env_memset(cmp_buffer, PAGE_SIZE, 0));

	ret = __ocf_mngt_init_test_device_submit_and_cmp(cache,
			reserved_lba_addr, rw_buffer, cmp_buffer, &diff);
	if (ret)
		goto end;

	if (diff) {
		/* discard does not cause target adresses to return 0 on
		   subsequent read */
		cache->device->obj.features.discard_zeroes = 0;
	}

end:
	env_free(rw_buffer);
	env_free(cmp_buffer);

	return ret;
}

/**
 * Prepare metadata accordingly to mode (for load/recovery read from disk)
 */
static int _ocf_mngt_init_prepare_metadata(
		struct ocf_cachemng_attach_params *attach_params)
{
	int ret;
	int i;
	ocf_cache_t cache = attach_params->cache;
	ocf_cache_line_size_t line_size = attach_params->metadata.line_size ?
						attach_params->metadata.line_size :
						cache->metadata.settings.size;

	OCF_ASSERT_PLUGGED(cache);

	if (cache->device->init_mode != ocf_init_mode_metadata_volatile) {
		if (cache->device->init_mode == ocf_init_mode_load) {
			attach_params->metadata.status = ocf_metadata_load_properties(
					&cache->device->obj,
					&line_size,
					&cache->conf_meta->metadata_layout,
					&cache->conf_meta->cache_mode,
					&attach_params->metadata.shutdown_status,
					&attach_params->metadata.dirty_flushed);
			if (attach_params->metadata.status) {
				ret = -OCF_ERR_START_CACHE_FAIL;
				return ret;
			}
		} else {
			attach_params->metadata.status = ocf_metadata_load_properties(
					&cache->device->obj,
					NULL, NULL, NULL,
					&attach_params->metadata.shutdown_status,
					&attach_params->metadata.dirty_flushed);
			/* don't handle result; if no valid metadata is present
			 * on caching device, we are about to use, it's not an issue
			 */
		}
	}

	/*
	 * Initialize variable size metadata segments
	 */
	if (ocf_metadata_init_variable_size(cache, attach_params->device_size,
			line_size,
			cache->conf_meta->metadata_layout)) {
		return -OCF_ERR_START_CACHE_FAIL;

	}
	ocf_cache_log(cache, log_debug, "Cache attached\n");
	attach_params->flags.attached_metadata_inited = true;

	for (i = 0; i < OCF_IO_CLASS_MAX + 1; ++i) {
		cache->user_parts[i].runtime =
				&cache->device->runtime_meta->user_parts[i];
	}

	cache->device->freelist_part = &cache->device->runtime_meta->freelist_part;

	ret = ocf_concurrency_init(cache);
	if (!ret)
		attach_params->flags.concurrency_inited = 1;

	return ret;
}

/**
 * @brief initializing cache anew (not loading or recovering)
 */
static int _ocf_mngt_init_instance_init(struct ocf_cachemng_attach_params *attach_params)
{
	struct ocf_cache *cache = attach_params->cache;

	if (!attach_params->metadata.status && !attach_params->force &&
			attach_params->metadata.shutdown_status !=
					ocf_metadata_detached) {

		if (attach_params->metadata.shutdown_status !=
				ocf_metadata_clean_shutdown) {
			ocf_cache_log(cache, log_err, DIRTY_SHUTDOWN_ERROR_MSG);
			return -OCF_ERR_DIRTY_SHUTDOWN;
		}

		if (attach_params->metadata.dirty_flushed == DIRTY_NOT_FLUSHED) {
			ocf_cache_log(cache, log_err,
					DIRTY_NOT_FLUSHED_ERROR_MSG);
			return -OCF_ERR_DIRTY_EXISTS;
		}
	}

	init_attached_data_structures(cache,
			attach_params->cache->eviction_policy_init);

	/* In initial cache state there is no dirty data, so all dirty data is
	   considered to be flushed
	 */
	cache->conf_meta->dirty_flushed = true;
	if (ocf_metadata_flush_all(cache)) {
		ocf_cache_log(cache, log_err,
				"ERROR: Cannot save cache state\n");
		return -OCF_ERR_WRITE_CACHE;
	}

	return 0;
}

static int check_ram_availability(ocf_ctx_t ctx,
		struct ocf_cachemng_attach_params  *attach_params)
{
	struct ocf_cache *cache = attach_params->cache;
	ocf_cache_line_size_t line_size = cache->metadata.settings.size;
	uint64_t const_data_size;
	uint64_t cache_line_no;
	uint64_t data_per_line;
	uint64_t free_ram;

	/* Superblock + per core metadata */
	const_data_size = 50 * MiB;

	/* Cache metadata */
	cache_line_no = attach_params->device_size / line_size;
	data_per_line = (52 + (2 * (line_size / KiB / 4)));

	attach_params->min_free_ram = const_data_size + cache_line_no * data_per_line;

	/* 110% of calculated value */
	attach_params->min_free_ram = (11 * attach_params->min_free_ram) / 10;

	free_ram = env_get_free_memory();

	if (free_ram < attach_params->min_free_ram) {
		ocf_log(ctx, log_err, "Not enough free RAM for cache "
				"metadata to start cache\n");
		ocf_log(ctx, log_err, "Available RAM: %" ENV_PRIu64 " B\n",
				free_ram);
		ocf_log(ctx, log_err, "Needed RAM: %" ENV_PRIu64 " B\n",
				attach_params->min_free_ram);
		return -OCF_ERR_NO_FREE_RAM;
	}

	return 0;
}

/**
 * finalize init instance action
 * (same handling for all three initialization modes)
 */
static int _ocf_mngt_init_post_action(struct ocf_cachemng_attach_params *attach_params)
{
	int result = 0;
	struct ocf_cache *cache = attach_params->cache;

	/* clear clean shutdown status */
	if (ocf_metadata_set_shutdown_status(cache,
				ocf_metadata_dirty_shutdown)) {
		ocf_cache_log(cache, log_err, "Cannot flush shutdown status\n");
		return -OCF_ERR_WRITE_CACHE;
	}

	if (!attach_params->flags.cleaner_started) {
		result = ocf_start_cleaner(cache);
		if (result) {
			ocf_cache_log(cache, log_err,
					"Error while starting cleaner\n");
			return result;
		}
		attach_params->flags.cleaner_started = true;
	}

	env_waitqueue_init(&cache->pending_dirty_wq);
	env_waitqueue_init(&cache->pending_cache_wq);

	env_atomic_set(&cache->attached, 1);

	return 0;
}

/**
 * @brief for error handling do partial cleanup of datastructures upon
 * premature function exit.
 *
 * @param cache cache instance
 * @param ctx OCF context
 * @param params - startup params containing initialization status flags.
 *		Value of NULL indicates cache is fully initialized but not
 *		handling any I/O (cache->valid_ocf_cache_device_t is 0).
 */
static void _ocf_mngt_init_handle_error(ocf_cache_t cache,
		ocf_ctx_t ctx, struct ocf_cachemng_init_params *params)
{
	if (!params || params->flags.io_queues_started)
		ocf_stop_queues(cache);

	if (!params || params->flags.queues_inited)
		ocf_free_queues(cache);

	if (!params || params->flags.metadata_inited)
		ocf_metadata_deinit(cache);

	env_mutex_lock(&ctx->lock);

	if (!params || params->flags.cache_alloc) {
		list_del(&cache->list);
		env_vfree(cache);
	}

	env_mutex_unlock(&ctx->lock);
}

static void _ocf_mngt_attach_handle_error(
	struct ocf_cachemng_attach_params *attach_params)
{
	struct ocf_cache *cache = attach_params->cache;

	if (attach_params->flags.cleaner_started)
		ocf_stop_cleaner(cache);

	if (attach_params->flags.cores_opened)
		_ocf_mngt_close_all_uninitialized_cores(cache);

	if (attach_params->flags.attached_metadata_inited)
		ocf_metadata_deinit_variable_size(cache);

	if (attach_params->flags.device_opened)
		ocf_dobj_close(&cache->device->obj);

	if (attach_params->flags.concurrency_inited)
		ocf_concurrency_deinit(cache);

	if (attach_params->flags.data_obj_inited)
		ocf_dobj_deinit(&cache->device->obj);

	if (attach_params->flags.device_alloc)
		env_vfree(cache->device);
}

static int _ocf_mngt_cache_discard_after_metadata(struct ocf_cache *cache)
{
	int result;
	uint64_t addr = cache->device->metadata_offset;
	uint64_t length = ocf_dobj_get_length(
			&cache->device->obj) - addr;
	bool discard = cache->device->obj.features.discard_zeroes;

	if (!discard &&	ocf_dobj_is_atomic(&cache->device->obj)) {
		/* discard does not zero data - need to explicitly write
		    zeroes */
		result = ocf_submit_write_zeroes_wait(
				&cache->device->obj, addr, length);
		if (!result) {
			result = ocf_submit_obj_flush_wait(
					&cache->device->obj);
		}
	} else {
		/* Discard object after metadata */
		result = ocf_submit_obj_discard_wait(&cache->device->obj, addr,
				length);
	}

	if (result) {
		ocf_cache_log(cache, log_warn, "%s failed\n",
				discard ? "Discarding whole cache device" :
					"Overwriting cache with zeroes");

		if (ocf_dobj_is_atomic(&cache->device->obj)) {
			ocf_cache_log(cache, log_err, "This step is required"
					" for atomic mode!\n");
		} else {
			ocf_cache_log(cache, log_warn, "This may impact cache"
					" performance!\n");
			result = 0;
		}
	}

	return result;
}

static int _ocf_mngt_cache_init(ocf_cache_t cache,
		struct ocf_cachemng_init_params *params)
{
	int i;
	int result;

	/*
	 * Super block elements initialization
	 */
	cache->conf_meta->cache_mode = params->metadata.cache_mode;
	cache->conf_meta->metadata_layout = params->metadata.layout;

	for (i = 0; i < OCF_IO_CLASS_MAX + 1; ++i) {
		cache->user_parts[i].config =
				&cache->conf_meta->user_parts[i];
	}

	result = ocf_alloc_queues(cache);
	if (result)
		return result;
	params->flags.queues_inited = 1;

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

	result = _ocf_mngt_cache_init(*cache, &params);
	if (result)
		goto _cache_mng_init_instance_ERROR;

	ocf_log(ctx, log_debug, "Metadata initialized\n");
	params.flags.metadata_inited = true;

	if (!params.flags.io_queues_started) {
		result = ocf_start_queues(*cache);
		if (result) {
			ocf_log(ctx, log_err,
					"Error while creating I/O queues\n");
			return result;
		}
		params.flags.io_queues_started = true;
	}

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
	_ocf_mngt_init_handle_error(params.cache, ctx, &params);
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
			if (!env_bit_test(i, cache->conf_meta->valid_object_bitmap))
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
		if (env_bit_test(i, cache->conf_meta->valid_object_bitmap))
			cleaning_policy_ops[clean_type].remove_core(cache, i);
	};

	return result;
}

static void _ocf_mngt_init_attached_nonpersistent(ocf_cache_t cache)
{
	env_atomic_set(&cache->fallback_pt_error_counter, 0);
}

static int _ocf_mngt_cache_attach(ocf_cache_t cache,
		struct ocf_mngt_cache_device_config *device_cfg,
		bool load)

{
	struct ocf_cachemng_attach_params attach_params;
	int result;

	ENV_BUG_ON(env_memset(&attach_params, sizeof(attach_params), 0));

	if (cache->metadata.is_volatile && load)
		return -EINVAL;

	attach_params.force = device_cfg->force;
	attach_params.uuid = device_cfg->uuid;
	attach_params.device_type = device_cfg->data_obj_type;
	attach_params.perform_test = device_cfg->perform_test;
	attach_params.metadata.shutdown_status = ocf_metadata_clean_shutdown;
	attach_params.metadata.dirty_flushed = DIRTY_FLUSHED;
	attach_params.metadata.line_size = device_cfg->cache_line_size;
	attach_params.cache = cache;
	attach_params.load = load;

	 _ocf_mngt_init_attached_nonpersistent(cache);

	result = _ocf_mngt_attach_cache_device(cache, &attach_params);
	if (result)
		goto _cache_mng_init_attach_ERROR;

	result = check_ram_availability(ocf_cache_get_ctx(cache),
			&attach_params);
	device_cfg->min_free_ram = attach_params.min_free_ram;
	if (result)
		goto _cache_mng_init_attach_ERROR;

	/* Prepare metadata */
	result = _ocf_mngt_init_prepare_metadata(&attach_params);
	if (result)
		goto _cache_mng_init_attach_ERROR;

	/* Test device features */
	cache->device->obj.features.discard_zeroes = 1;
	if (attach_params.perform_test) {
		result = _ocf_mngt_init_test_device(cache);
		if (result)
			goto _cache_mng_init_attach_ERROR;
	}

	switch (cache->device->init_mode) {
	case ocf_init_mode_init:
	case ocf_init_mode_metadata_volatile:
		result = _ocf_mngt_init_instance_init(&attach_params);
		break;
	case ocf_init_mode_load:
		result = _ocf_mngt_init_instance_load(&attach_params);
		break;
	default:
		result = OCF_ERR_INVAL;
	}

	if (result)
		goto _cache_mng_init_attach_ERROR;

	/* Discard whole device after metadata if it's a new instance. */
	if (device_cfg->discard_on_start && cache->device->init_mode !=
			ocf_init_mode_load) {
		result = _ocf_mngt_cache_discard_after_metadata(cache);
		if (result)
			goto _cache_mng_init_attach_ERROR;
	}

	if (cache->device->init_mode != ocf_init_mode_load) {
		result = _ocf_mngt_cache_add_cores_t_clean_pol(cache);
		if (result)
			goto _cache_mng_init_attach_ERROR;
	}

	result = _ocf_mngt_init_post_action(&attach_params);
	if (result)
		goto _cache_mng_init_attach_ERROR;

	return 0;

_cache_mng_init_attach_ERROR:
	_ocf_mngt_attach_handle_error(&attach_params);
	return result;
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

	if (!cfg->io_queues)
		return -OCF_ERR_INVAL;

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

	if (device_cfg->uuid.size > OCF_DATA_OBJ_UUID_MAX_SIZE)
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

int ocf_mngt_cache_attach(ocf_cache_t cache,
		struct ocf_mngt_cache_device_config *device_cfg)
{
	int result;

	if (!cache || !device_cfg)
		return -OCF_ERR_INVAL;

	result = _ocf_mngt_cache_validate_device_cfg(device_cfg);
	if (result)
		return result;

	result = _ocf_mngt_cache_attach(cache, device_cfg, false);
	if (!result) {
		ocf_cache_log(cache, log_info, "Successfully attached\n");
	} else {
		ocf_cache_log(cache, log_err, "Attaching cache device "
			       "failed\n");
	}

	return result;
}

/**
 * @brief Unplug caching device from cache instance. Variable size metadata
 *	  containers are deinitialiazed as well as other cacheline related
 *	  structures. Cache device object is closed.
 *
 * @param cache OCF cache instance
 * @param stop	- true if unplugging during stop - in this case we mark
 *		    clean shutdown in metadata and flush all containers.
 *		- false if the device is to be detached from cache - loading
 *		    metadata from this device will not be possible.
 *
 * @retval 0 operation successfull
 * @retval non-zero error status
 */
static int _ocf_mngt_cache_unplug(ocf_cache_t cache, bool stop)
{
	int result;

	if (stop)
		ENV_BUG_ON(cache->conf_meta->core_count != 0);

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
		result = ocf_metadata_set_shutdown_status(cache,
				ocf_metadata_detached);
	} else {
		/* Flush metadata */
		result = ocf_metadata_flush_all(cache);
	}

	ocf_dobj_close(&cache->device->obj);

	ocf_metadata_deinit_variable_size(cache);
	ocf_concurrency_deinit(cache);

	ocf_dobj_deinit(&cache->device->obj);

	env_vfree(cache->device);
	cache->device = NULL;
	env_atomic_set(&cache->attached, 0);

	/* TODO: this should  be removed from detach after 'attached' stats
		are better separated in statistics */
	_ocf_mngt_init_attached_nonpersistent(cache);

	if (result)
		return -OCF_ERR_WRITE_CACHE;

	return 0;
}

static int _ocf_mngt_cache_stop(ocf_cache_t cache)
{
	int i, j, no, result = 0;
	ocf_ctx_t owner = cache->owner;

	no = cache->conf_meta->core_count;

	env_bit_set(ocf_cache_state_stopping, &cache->cache_state);
	env_bit_clear(ocf_cache_state_running, &cache->cache_state);

	ocf_mngt_wait_for_io_finish(cache);

	/* All exported objects removed, cleaning up rest. */
	for (i = 0, j = 0; j < no && i < OCF_CORE_MAX; i++) {
		if (!env_bit_test(i, cache->conf_meta->valid_object_bitmap))
			continue;
		cache_mng_core_remove_from_cache(cache, i);
		if (ocf_cache_is_device_attached(cache))
			cache_mng_core_remove_from_cleaning_pol(cache, i);
		cache_mng_core_close(cache, i);
		j++;
	}
	ENV_BUG_ON(cache->conf_meta->core_count != 0);

	if (env_atomic_read(&cache->attached))
		result = _ocf_mngt_cache_unplug(cache, true);

	ocf_stop_queues(cache);

	env_mutex_lock(&owner->lock);
	/* Mark device uninitialized */
	cache->valid_ocf_cache_device_t = 0;
	/* Remove cache from the list */
	list_del(&cache->list);
	/* Finally release cache instance */
	ocf_mngt_cache_put(cache);
	env_mutex_unlock(&owner->lock);

	return result;
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

int ocf_mngt_cache_load(ocf_ctx_t ctx, ocf_cache_t *cache,
		struct ocf_mngt_cache_config *cfg,
		struct ocf_mngt_cache_device_config *device_cfg)
{
	int result;

	if (!ctx || !cache || !cfg || !device_cfg)
		return -OCF_ERR_INVAL;

	result = _ocf_mngt_cache_validate_cfg(cfg);
	if (result)
		return result;

	result = _ocf_mngt_cache_validate_device_cfg(device_cfg);
	if (result)
		return result;

	result = _ocf_mngt_cache_start(ctx, cache, cfg);
	if (!result) {
		ocf_cache_log(*cache, log_info, "Successfully added\n");
	} else {
		if (cfg->name) {
			ocf_log(ctx, log_err, "Inserting cache %s failed\n",
					cfg->name);
		} else {
			ocf_log(ctx, log_err, "Inserting cache failed\n");
		}
		return result;
	}

	result =  _ocf_mngt_cache_attach(*cache, device_cfg, true);
	if (result) {
		_ocf_mngt_init_handle_error(*cache, ctx, NULL);
		return result;
	}

	_ocf_mng_cache_set_valid(*cache);

	_ocf_mngt_cache_load_log(*cache);

	return 0;
}

int ocf_mngt_cache_stop(ocf_cache_t cache)
{
	int result;
	char cache_name[OCF_CACHE_NAME_SIZE];
	ocf_ctx_t context;

	OCF_CHECK_NULL(cache);

	result = env_strncpy(cache_name, sizeof(cache_name),
			ocf_cache_get_name(cache), sizeof(cache_name));
	if (result)
		return result;

	context = ocf_cache_get_ctx(cache);

	ocf_cache_log(cache, log_info, "Stopping cache\n");

	result = _ocf_mngt_cache_stop(cache);

	if (result == -OCF_ERR_WRITE_CACHE) {
		ocf_log(context, log_warn, "Stopped cache %s with "
				"errors\n", cache_name);
	} else if (result) {
		ocf_log(context, log_err, "Stopping cache %s "
				"failed\n", cache_name);
	} else {
		ocf_log(context, log_info, "Cache %s successfully "
				"stopped\n", cache_name);
	}

	return result;
}

static int _cache_mng_set_cache_mode(ocf_cache_t cache, ocf_cache_mode_t mode,
		uint8_t flush)
{
	ocf_cache_mode_t mode_new = mode;
	ocf_cache_mode_t mode_old = cache->conf_meta->cache_mode;
	int result = 0;

	/* Check if IO interface type is valid */
	if (!ocf_cache_mode_is_valid(mode))
		return -OCF_ERR_INVAL;

	if (mode_new == mode_old) {
		ocf_cache_log(cache, log_info, "Cache mode '%s' is already set\n",
				ocf_get_io_iface_name(mode_new));
		return 0;
	}

	cache->conf_meta->cache_mode = mode_new;

	if (flush) {
		/* Flush required, do it, do it, do it... */
		result = ocf_mngt_cache_flush(cache, true);

		if (result) {
			cache->conf_meta->cache_mode = mode_old;
			return result;
		}

	} else if (ocf_cache_mode_wb == mode_old) {
		int i;

		for (i = 0; i != OCF_CORE_MAX; ++i) {
			if (!env_bit_test(i, cache->conf_meta->valid_object_bitmap))
				continue;
			env_atomic_set(&cache->core_runtime_meta[i].
					initial_dirty_clines,
					env_atomic_read(&cache->
						core_runtime_meta[i].dirty_clines));
		}
	}

	if (ocf_metadata_flush_superblock(cache)) {
		ocf_cache_log(cache, log_err, "Failed to store cache mode "
				"change. Reverting\n");
		cache->conf_meta->cache_mode = mode_old;
		return -OCF_ERR_WRITE_CACHE;
	}

	ocf_cache_log(cache, log_info, "Changing cache mode from '%s' to '%s' "
			"successful\n", ocf_get_io_iface_name(mode_old),
			ocf_get_io_iface_name(mode_new));

	return 0;
}

int ocf_mngt_cache_set_mode(ocf_cache_t cache, ocf_cache_mode_t mode,
		uint8_t flush)
{
	int result;

	OCF_CHECK_NULL(cache);

	if (!ocf_cache_mode_is_valid(mode)) {
	        ocf_cache_log(cache, log_err, "Cache mode %u is invalid\n", mode);
		return -OCF_ERR_INVAL;
	}

	result = _cache_mng_set_cache_mode(cache, mode, flush);

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

int ocf_mngt_cache_detach(ocf_cache_t cache)
{
	int i, j, no;
	int result;

	OCF_CHECK_NULL(cache);

	no = cache->conf_meta->core_count;

	if (!env_atomic_read(&cache->attached))
		return -EINVAL;

	/* prevent dirty io */
	env_atomic_inc(&cache->flush_started);

	result = ocf_mngt_cache_flush(cache, true);
	if (result)
		return result;

	/* wait for all requests referencing cacheline metadata to finish */
	env_atomic_set(&cache->attached, 0);
	env_waitqueue_wait(cache->pending_cache_wq,
			!env_atomic_read(&cache->pending_cache_requests));

	ENV_BUG_ON(env_atomic_dec_return(&cache->flush_started) < 0);

	/* remove cacheline metadata and cleaning policy meta for all cores */
	for (i = 0, j = 0; j < no && i < OCF_CORE_MAX; i++) {
		if (!env_bit_test(i, cache->conf_meta->valid_object_bitmap))
			continue;
		cache_mng_core_deinit_attached_meta(cache, i);
		cache_mng_core_remove_from_cleaning_pol(cache, i);
		j++;
	}

	/* Do the actual detach - deinit cacheline metadata, stop cleaner
	   thread and close cache bottom device */
	result = _ocf_mngt_cache_unplug(cache, false);

	if (!result) {
		ocf_cache_log(cache, log_info, "Successfully detached\n");
	} else {
		if (result == -OCF_ERR_WRITE_CACHE) {
			ocf_cache_log(cache, log_warn,
					"Detached cache with errors\n");
		} else {
			ocf_cache_log(cache, log_err,
					"Detaching cache failed\n");
		}
	}

	return result;
}
