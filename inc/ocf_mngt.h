/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_MNGT_H__
#define __OCF_MNGT_H__

#include "ocf_types.h"
#include "ocf_cache.h"
#include "ocf_core.h"

/**
 * @file
 * @brief OCF management operations definitions
 */

/**
 * @brief Core start configuration
 */
struct ocf_mngt_core_config {
	/**
	 * @brief OCF core volume UUID
	 */
	struct ocf_volume_uuid uuid;

	/**
	 * @brief OCF core volume type
	 */
	uint8_t volume_type;

	/**
	 * @brief OCF core ID number
	 */
	ocf_core_id_t core_id;

	/**
	 * @brief OCF core name. In case of being NULL, core id is stringified
	 *	to core name
	 */
	const char *name;

	/**
	 * @brief OCF cache ID number
	 */
	ocf_cache_id_t cache_id;

	/**
	 * @brief Add core to pool if cache isn't present or add core to
	 *	earlier loaded cache
	 */
	bool try_add;

	uint32_t seq_cutoff_threshold;
		/*!< Sequential cutoff threshold (in bytes) */

	struct {
		void *data;
		size_t size;
	} user_metadata;
};

/**
 * @brief Get number of OCF caches
 *
 * @param[in] ctx OCF context
 *
 * @retval Number of caches in given OCF instance
 */
uint32_t ocf_mngt_cache_get_count(ocf_ctx_t ctx);

/* Cache instances getters */

/**
 * @brief Get OCF cache
 *
 * @note This function on success also increasing reference counter in given
 *		cache
 *
 * @param[in] ctx OCF context
 * @param[in] id OCF cache ID
 * @param[out] cache OCF cache handle
 *
 * @retval 0 Get cache successfully
 * @retval -OCF_ERR_INV_CACHE_ID Cache ID out of range
 * @retval -OCF_ERR_CACHE_NOT_EXIST Cache with given ID is not exist
 */
int ocf_mngt_cache_get(ocf_ctx_t ctx, ocf_cache_id_t id, ocf_cache_t *cache);

/**
 * @brief Decrease reference counter in cache
 *
 * @note If cache don't have any reference - deallocate it
 *
 * @param[in] cache Handle to cache
 */
void ocf_mngt_cache_put(ocf_cache_t cache);

/**
 * @brief Lock cache for management oparations (write lock, exclusive)
 *
 * @param[in] cache Handle to cache
 *
 * @retval 0 Cache successfully locked
 * @retval -OCF_ERR_CACHE_NOT_EXIST Can not lock cache - cache is already
 *					stopping
 * @retval -OCF_ERR_CACHE_IN_USE Can not lock cache - cache is in use
 * @retval -OCF_ERR_INTR Wait operation interrupted
 */
int ocf_mngt_cache_lock(ocf_cache_t cache);

/**
 * @brief Lock cache for read - assures cache config does not change while
 *		lock is being held, while allowing other users to acquire
 *		read lock in parallel.
 *
 * @param[in] cache Handle to cache
 *
 * @retval 0 Cache successfully locked
 * @retval -OCF_ERR_CACHE_NOT_EXIST Can not lock cache - cache is already
 *					stopping
 * @retval -OCF_ERR_CACHE_IN_USE Can not lock cache - cache is in use
 * @retval -OCF_ERR_INTR Wait operation interrupted
 */
int ocf_mngt_cache_read_lock(ocf_cache_t cache);

/**
 * @brief Lock cache for management oparations (write lock, exclusive)
 *
 * @param[in] cache Handle to cache
 *
 * @retval 0 Cache successfully locked
 * @retval -OCF_ERR_CACHE_NOT_EXIST Can not lock cache - cache is already
 *					stopping
 * @retval -OCF_ERR_CACHE_IN_USE Can not lock cache - cache is in use
 * @retval -OCF_ERR_NO_LOCK Lock not acquired
 */
int ocf_mngt_cache_trylock(ocf_cache_t cache);

/**
 * @brief Lock cache for read - assures cache config does not change while
 *		lock is being held, while allowing other users to acquire
 *		read lock in parallel.
 *
 * @param[in] cache Handle to cache
 *
 * @retval 0 Cache successfully locked
 * @retval -OCF_ERR_CACHE_NOT_EXIST Can not lock cache - cache is already
 *					stopping
 * @retval -OCF_ERR_CACHE_IN_USE Can not lock cache - cache is in use
 * @retval -OCF_ERR_NO_LOCK Lock not acquired
 */
int ocf_mngt_cache_read_trylock(ocf_cache_t cache);

/**
 * @brief Write-unlock cache
 *
 * @param[in] cache Handle to cache
 */
void ocf_mngt_cache_unlock(ocf_cache_t cache);

/**
 * @brief Read-unlock cache
 *
 * @param[in] cache Handle to cache
 */
void ocf_mngt_cache_read_unlock(ocf_cache_t cache);

/**
 * @brief Cache visitor function
 *
 * @param[in] cache Handle to cache
 * @param[in] cntx Visitor function context
 *
 * @retval 0 Success
 * @retval Non-zero Error
 */
typedef int (*ocf_mngt_cache_visitor_t)(ocf_cache_t cache, void *cntx);

/**
 * @brief Loop for each cache
 *
 * @note Visitor function is called for each cache
 *
 * @param[in] ctx OCF context
 * @param[in] visitor OCF cache visitor function
 * @param[in] cntx Context for cache visitor function
 *
 * @retval 0 Success
 * @retval Non-zero Error
 */
int ocf_mngt_cache_visit(ocf_ctx_t ctx, ocf_mngt_cache_visitor_t visitor,
		void *cntx);

/**
 * @brief Loop for each cache reverse
 *
 * @note Visitor function is called for each cache
 *
 * @param[in] ctx OCF context
 * @param[in] visitor OCF cache visitor function
 * @param[in] cntx Context for cache visitor function
 *
 * @retval 0 Success
 * @retval Non-zero Error
 */
int ocf_mngt_cache_visit_reverse(ocf_ctx_t ctx, ocf_mngt_cache_visitor_t visitor,
		void *cntx);

/**
 * @brief Cache probe status
 */
struct ocf_mngt_cache_probe_status {
	/**
	 * @brief Gracefully shutdown for cache detected
	 */
	bool clean_shutdown;

	/**
	 * @brief Cache is dirty and requires flushing
	 */
	bool cache_dirty;
};

/**
 * @brief Cache start configuration
 */
struct ocf_mngt_cache_config {
	/**
	 * @brief Cache ID. In case of setting this field to invalid cache
	 *		id first available cache ID will be set
	 */
	ocf_cache_id_t id;

	/**
	 * @brief Cache name. In case of being NULL, cache id is stringified to
	 *		cache name
	 */
	const char *name;

	/**
	 * @brief Cache mode
	 */
	ocf_cache_mode_t cache_mode;

	/**
	 * @brief Eviction policy type
	 */
	ocf_eviction_t eviction_policy;

	/**
	 * @brief Cache line size
	 */
	ocf_cache_line_size_t cache_line_size;

	/**
	 * @brief Metadata layout (stripping/sequential)
	 */
	ocf_metadata_layout_t metadata_layout;

	bool metadata_volatile;

	/**
	 * @brief Backfill configuration
	 */
	struct {
		 uint32_t max_queue_size;
		 uint32_t queue_unblock_size;
	} backfill;

	/**
	 * @brief Start cache and keep it locked
	 *
	 * @note In this case caller is able to perform additional activities
	 *		and then shall unlock cache
	 */
	bool locked;

	/**
	 * @brief Use pass-through mode for I/O requests unaligned to 4KiB
	 */
	bool pt_unaligned_io;

	/**
	 * @brief If set, try to submit all I/O in fast path.
	 */
	bool use_submit_io_fast;
};

/**
 * @brief Cache attach configuration
 */
struct ocf_mngt_cache_device_config {
	/**
	 * @brief Cache volume UUID
	 */
	struct ocf_volume_uuid uuid;

	/**
	 * @brief Cache volume type
	 */
	uint8_t volume_type;

	/**
	 * @brief Cache line size
	 */
	ocf_cache_line_size_t cache_line_size;

	/**
	 * @brief Ignore warnings and start cache
	 *
	 * @note It will force starting cache despite the:
	 *	- overwrite dirty shutdown of previous cache
	 *	- ignore cache with dirty shutdown and reinitialize cache
	 */
	bool force;

	/**
	 * @brief Minimum free RAM required to start cache. Set during
	 *		cache start procedure
	 */
	uint64_t min_free_ram;

	/**
	 * @brief If set, cache features (like discard) are tested
	 *		before starting cache
	 */
	bool perform_test;

	/**
	 * @brief If set, cache device will be discarded on cache start
	 */
	bool discard_on_start;
};

/**
 * @brief Start cache instance
 *
 * @param[in] ctx OCF context
 * @param[out] cache Cache handle
 * @param[in] cfg Starting cache configuration
 *
 * @retval 0 Cache started successfully
 * @retval Non-zero Error occurred and starting cache failed
 */
int ocf_mngt_cache_start(ocf_ctx_t ctx, ocf_cache_t *cache,
		struct ocf_mngt_cache_config *cfg);

/**
 * @brief Stop cache instance
 *
 * @param[in] cache Cache handle
 *
 * @retval 0 Cache successfully stopped
 * @retval Non-zero Error occurred during stopping cache
 */
int ocf_mngt_cache_stop(ocf_cache_t cache);

/**
 * @brief Attach caching device to cache instance
 *
 * @param[in] cache Cache handle
 * @param[in] device_cfg Caching device configuration
 *
 * @retval 0 Cache cache successfully attached
 * @retval Non-zero Error occurred during attaching cache
 */
int ocf_mngt_cache_attach(ocf_cache_t cache,
		struct ocf_mngt_cache_device_config *device_cfg);

/**
 * @brief Detach caching cache
 *
 * @param[in] cache Cache handle
 *
 * @retval 0 Cache cache successfully detached
 * @retval Non-zero Error occurred during stopping cache
 */
int ocf_mngt_cache_detach(ocf_cache_t cache);

/**
 * @brief Load cache instance
 *
 * @param[in] ctx OCF context
 * @param[out] cache Cache handle
 * @param[in] device_cfg Caching device configuration
 *
 * @retval 0 Cache successfully loaded
 * @retval Non-zero Error occurred during loading cache
 */
int ocf_mngt_cache_load(ocf_ctx_t ctx, ocf_cache_t *cache,
		struct ocf_mngt_cache_device_config *device_cfg);

/* Adding and removing cores */

/**
 * @brief Add core to cache instance
 *
 * @param[in] cache Cache handle
 * @param[out] core Core object handle
 * @param[in] cfg Core configuration
 *
 * @retval 0 Core successfully added core to cache
 * @retval Non-zero Error occurred and adding core failed
 */
int ocf_mngt_cache_add_core(ocf_cache_t cache, ocf_core_t *core,
		struct ocf_mngt_core_config *cfg);

/**
 * @brief Remove core from cache instance
 *
 * @param[in] cache Core handle
 *
 * @retval 0 Core successfully removed from cache
 * @retval Non-zero Error occurred and removing core failed
 */
int ocf_mngt_cache_remove_core(ocf_core_t core);

/**
 * @brief Detach core from cache instance
 *
 * @param[in] core Core handle
 *
 * @retval 0 Core successfully detached from cache
 * @retval Non-zero Error occurred and detaching core failed
 */
int ocf_mngt_cache_detach_core(ocf_core_t core);

/* Flush operations */

/**
 * @brief Flush data from given cache
 *
 * @param[in] cache Cache handle
 * @param[in] interruption Allow for interruption
 *
 * @retval 0 Successfully flushed given cache
 * @retval Non-zero Error occurred and flushing cache failed
 */
int ocf_mngt_cache_flush(ocf_cache_t cache, bool interruption);

/**
 * @brief Flush data to given core
 *
 * @param[in] core Core handle
 * @param[in] interruption Allow for interruption
 *
 * @retval 0 Successfully flushed data to given core
 * @retval Non-zero Error occurred and flushing data to core failed
 */
int ocf_mngt_core_flush(ocf_core_t core, bool interruption);

/**
 * @brief Interrupt existing flushing of cache or core
 *
 * @param[in] cache Cache instance
 *
 * @retval 0 Operation success
 * @retval Non-zero Operation failure
 */
int ocf_mngt_cache_flush_interrupt(ocf_cache_t cache);

/**
 * @brief Purge data to given core
 *
 * @param[in] core Core handle
 * @param[in] interruption Allow for interruption
 *
 * @retval 0 Successfully purged data to given core
 * @retval Non-zero Error occurred and purging data to core failed
 */
int ocf_mngt_core_purge(ocf_core_t core, bool interruption);
/**
 * @brief Purge data from given cache
 *
 * @param[in] cache Cache handle
 * @param[in] interruption Allow for interruption
 *
 * @retval 0 Successfully purged given cache
 * @retval Non-zero Error occurred and purging cache failed
 */
int ocf_mngt_cache_purge(ocf_cache_t cache, bool interruption);

/**
 * @brief Set cleaning policy in given cache
 *
 * @param[in] cache Cache handle
 * @param[in] type Cleainig policy type
 *
 * @retval 0 Policy has been set successfully
 * @retval Non-zero Error occurred and policy has not been set
 */
int ocf_mngt_cache_cleaning_set_policy(ocf_cache_t cache, ocf_cleaning_t type);

/**
 * @brief Get current cleaning policy from given cache
 *
 * @param[in] cache Cache handle
 * @param[out] type Variable to store current cleaning policy type
 *
 * @retval 0 Policy has been get successfully
 * @retval Non-zero Error occurred and policy has not been get
 */
int ocf_mngt_cache_cleaning_get_policy(ocf_cache_t cache, ocf_cleaning_t *type);

/**
 * @brief Set cleaning parameter in given cache
 *
 * @param[in] cache Cache handle
 * @param[in] param_id Cleaning policy parameter id
 * @param[in] param_value Cleaning policy parameter value
 *
 * @retval 0 Parameter has been set successfully
 * @retval Non-zero Error occurred and parameter has not been set
 */
int ocf_mngt_cache_cleaning_set_param(ocf_cache_t cache, ocf_cleaning_t type,
		uint32_t param_id, uint32_t param_value);

/**
 * @brief Get cleaning parameter from given cache
 *
 * @param[in] cache Cache handle
 * @param[in] param_id Cleaning policy parameter id
 * @param[in] param_value Variable to store parameter value
 *
 * @retval 0 Parameter has been get successfully
 * @retval Non-zero Error occurred and parameter has not been get
 */
int ocf_mngt_cache_cleaning_get_param(ocf_cache_t cache,ocf_cleaning_t type,
		uint32_t param_id, uint32_t *param_value);

/**
 * @brief IO class configuration
 */
struct ocf_mngt_io_class_config {
	/**
	 * @brief IO class ID
	 */
	uint32_t class_id;

	/**
	 * @brief IO class name
	 */
	const char *name;

	/**
	 * @brief IO class eviction priority
	 */
	int16_t prio;

	/**
	 * @brief IO class cache mode
	 */
	ocf_cache_mode_t cache_mode;

	/**
	 * @brief IO class minimum size
	 */
	uint32_t min_size;

	/**
	 * @brief IO class maximum size
	 */
	uint32_t max_size;
};

struct ocf_mngt_io_classes_config {
	struct ocf_mngt_io_class_config config[OCF_IO_CLASS_MAX];
};

/**
 * @brief Configure IO classes in given cache
 *
 * @param[in] cache Cache handle
 * @param[in] cfg IO class configuration
 *
 * @retval 0 Configuration have been set successfully
 * @retval Non-zero Error occurred and configuration not been set
 */
int ocf_mngt_cache_io_classes_configure(ocf_cache_t cache,
		const struct ocf_mngt_io_classes_config *cfg);

/**
 * @brief Set core sequential cutoff threshold
 *
 * @param[in] core Core handle
 * @param[in] thresh threshold in bytes for sequential cutoff
 *
 * @retval 0 Sequential cutoff threshold has been set successfully
 * @retval Non-zero Error occured and threshold hasn't been updated
 */
int ocf_mngt_core_set_seq_cutoff_threshold(ocf_core_t core, uint32_t thresh);

/**
 * @brief Set sequential cutoff threshold for all cores in cache
 *
 * @param[in] cache Cache handle
 * @param[in] thresh threshold in bytes for sequential cutoff
 *
 * @retval 0 Sequential cutoff threshold has been set successfully
 * @retval Non-zero Error occured and threshold hasn't been updated
 */
int ocf_mngt_core_set_seq_cutoff_threshold_all(ocf_cache_t cache,
		uint32_t thresh);

/**
 * @brief Get core sequential cutoff threshold
 *
 * @param[in] core Core handle
 * @param[in] thresh threshold in bytes for sequential cutoff
 *
 * @retval 0 Sequential cutoff threshold has been get successfully
 * @retval Non-zero Error occured
 */
int ocf_mngt_core_get_seq_cutoff_threshold(ocf_core_t core, uint32_t *thresh);

/**
 * @brief Set core sequential cutoff policy
 *
 * @param[in] core Core handle
 * @param[in] policy sequential cutoff policy
 *
 * @retval 0 Sequential cutoff policy has been set successfully
 * @retval Non-zero Error occured and policy hasn't been updated
 */
int ocf_mngt_core_set_seq_cutoff_policy(ocf_core_t core,
		ocf_seq_cutoff_policy policy);

/**
 * @brief Set sequential cutoff policy for all cores in cache
 *
 * @param[in] cache Cache handle
 * @param[in] policy sequential cutoff policy
 *
 * @retval 0 Sequential cutoff policy has been set successfully
 * @retval Non-zero Error occured and policy hasn't been updated
 */
int ocf_mngt_core_set_seq_cutoff_policy_all(ocf_cache_t cache,
		ocf_seq_cutoff_policy policy);

/**
 * @brief Get core sequential cutoff policy
 *
 * @param[in] core Core handle
 * @param[in] policy sequential cutoff policy
 *
 * @retval 0 Sequential cutoff policy has been get successfully
 * @retval Non-zero Error occured
 */
int ocf_mngt_core_get_seq_cutoff_policy(ocf_core_t core,
		ocf_seq_cutoff_policy *policy);

/**
 * @brief Set cache mode in given cache
 *
 * @param[in] cache Cache handle
 * @param[in] mode Cache mode to set
 * @param[in] flush Perform flushing before switch cache mode
 *
 * @retval 0 Cache mode have been set successfully
 * @retval Non-zero Error occurred and cache mode not been set
 */
int ocf_mngt_cache_set_mode(ocf_cache_t cache, ocf_cache_mode_t mode,
		uint8_t flush);

/**
 * @brief Set cache fallback Pass Through error threshold
 *
 * @param[in] cache Cache handle
 * @param[in] threshold Value to be set as threshold
 *
 * @retval 0 Fallback-PT threshold have been set successfully
 * @retval Non-zero Error occurred
 */
int ocf_mngt_cache_set_fallback_pt_error_threshold(ocf_cache_t cache,
		uint32_t threshold);

/**
 * @brief Get cache fallback Pass Through error threshold
 *
 * @param[in] cache Cache handle
 * @param[out] threshold Fallback-PT threshold
 *
 * @retval 0 Fallback-PT threshold have been get successfully
 * @retval Non-zero Error occurred
 */
int ocf_mngt_cache_get_fallback_pt_error_threshold(ocf_cache_t cache,
		uint32_t *threshold);

/**
 * @brief Reset cache fallback Pass Through error counter
 *
 * @param[in] cache Cache handle
 *
 * @retval 0 Threshold have been reset successfully
 */
int ocf_mngt_cache_reset_fallback_pt_error_counter(ocf_cache_t cache);

/**
 * @brief Initialize core pool
 *
 * @param[in] ctx OCF context
 */
void ocf_mngt_core_pool_init(ocf_ctx_t ctx);

/**
 * @brief Get core pool count
 *
 * @param[in] ctx OCF context
 *
 * @retval Number of cores in core pool
 */
int ocf_mngt_core_pool_get_count(ocf_ctx_t ctx);

/**
 * @brief Add core to pool
 *
 * @param[in] ctx OCF context
 * @param[in] uuid Cache volume UUID
 * @param[in] type OCF core volume type
 *
 * @retval 0 Core added to pool successfully
 * @retval Non-zero Error occurred and adding core to poll failed
 */
int ocf_mngt_core_pool_add(ocf_ctx_t ctx, ocf_uuid_t uuid, uint8_t type);

/**
 * @brief Add core to pool
 *
 * @param[in] ctx OCF context
 * @param[in] uuid Cache volume UUID
 * @param[in] type OCF core volume type
 *
 * @retval Handler to object with same UUID
 * @retval NULL Not found object with that id
 */
ocf_volume_t ocf_mngt_core_pool_lookup(ocf_ctx_t ctx, ocf_uuid_t uuid,
		ocf_volume_type_t type);
/**
 * @brief Iterate over all object in pool and call visitor callback
 *
 * @param[in] ctx OCF context
 * @param[in] visitor Visitor callback
 * @param[in] visior_ctx CContext for visitor callback
 *
 * @retval Handler to object with same UUID
 * @retval NULL Not found object with that id
 */
int ocf_mngt_core_pool_visit(ocf_ctx_t ctx,
		int (*visitor)(ocf_uuid_t, void *), void *visitor_ctx);

/**
 * @brief Remove volume from pool
 *
 * Important: This function destroys volume instance but doesn't close it,
 * so it should be either moved or closed before calling this function.
 *
 * @param[in] ctx OCF context
 * @param[in] volume Core volume
 */
void ocf_mngt_core_pool_remove(ocf_ctx_t ctx, ocf_volume_t volume);

/**
 * @brief Deinit core pool
 *
 * @param[in] ctx OCF context
 */
void ocf_mngt_core_pool_deinit(ocf_ctx_t ctx);

#endif /* __OCF_CACHE_H__ */
