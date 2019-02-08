/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_H__
#define __METADATA_H__

#include "../ocf_cache_priv.h"
#include "../ocf_ctx_priv.h"

static inline void ocf_metadata_eviction_lock(struct ocf_cache *cache)
{
	env_spinlock_lock(&cache->metadata.lock.eviction);
}

static inline void ocf_metadata_eviction_unlock(struct ocf_cache *cache)
{
	env_spinlock_unlock(&cache->metadata.lock.eviction);
}

#define OCF_METADATA_EVICTION_LOCK() \
		ocf_metadata_eviction_lock(cache)

#define OCF_METADATA_EVICTION_UNLOCK() \
		ocf_metadata_eviction_unlock(cache)

static inline void ocf_metadata_lock(struct ocf_cache *cache, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwsem_down_write(&cache->metadata.lock.collision);
	else if (rw == OCF_METADATA_RD)
		env_rwsem_down_read(&cache->metadata.lock.collision);
	else
		ENV_BUG();
}


static inline void ocf_metadata_unlock(struct ocf_cache *cache, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwsem_up_write(&cache->metadata.lock.collision);
	else if (rw == OCF_METADATA_RD)
		env_rwsem_up_read(&cache->metadata.lock.collision);
	else
		ENV_BUG();
}

static inline int ocf_metadata_try_lock(struct ocf_cache *cache, int rw)
{
	int result = -1;

	if (rw == OCF_METADATA_WR) {
		result = env_rwsem_down_write_trylock(
				&cache->metadata.lock.collision);
	} else if (rw == OCF_METADATA_RD) {
		result = env_rwsem_down_read_trylock(
				&cache->metadata.lock.collision);
	} else {
		ENV_BUG();
	}

	if (!result)
		return -1;

	return 0;
}

static inline void ocf_metadata_status_bits_lock(
		struct ocf_cache *cache, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwlock_write_lock(&cache->metadata.lock.status);
	else if (rw == OCF_METADATA_RD)
		env_rwlock_read_lock(&cache->metadata.lock.status);
	else
		ENV_BUG();
}

static inline void ocf_metadata_status_bits_unlock(
		struct ocf_cache *cache, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwlock_write_unlock(&cache->metadata.lock.status);
	else if (rw == OCF_METADATA_RD)
		env_rwlock_read_unlock(&cache->metadata.lock.status);
	else
		ENV_BUG();
}

#define OCF_METADATA_LOCK_RD() \
		ocf_metadata_lock(cache, OCF_METADATA_RD)

#define OCF_METADATA_UNLOCK_RD() \
		ocf_metadata_unlock(cache, OCF_METADATA_RD)

#define OCF_METADATA_LOCK_RD_TRY() \
		ocf_metadata_try_lock(cache, OCF_METADATA_RD)

#define OCF_METADATA_LOCK_WR() \
		ocf_metadata_lock(cache, OCF_METADATA_WR)

#define OCF_METADATA_LOCK_WR_TRY() \
		ocf_metadata_try_lock(cache, OCF_METADATA_WR)

#define OCF_METADATA_UNLOCK_WR() \
		ocf_metadata_unlock(cache, OCF_METADATA_WR)

#define OCF_METADATA_BITS_LOCK_RD() \
		ocf_metadata_status_bits_lock(cache, OCF_METADATA_RD)

#define OCF_METADATA_BITS_UNLOCK_RD() \
		ocf_metadata_status_bits_unlock(cache, OCF_METADATA_RD)

#define OCF_METADATA_BITS_LOCK_WR() \
		ocf_metadata_status_bits_lock(cache, OCF_METADATA_WR)

#define OCF_METADATA_BITS_UNLOCK_WR() \
		ocf_metadata_status_bits_unlock(cache, OCF_METADATA_WR)

#define OCF_METADATA_FLUSH_LOCK() \
		ocf_metadata_flush_lock(cache)

#define OCF_METADATA_FLUSH_UNLOCK() \
		ocf_metadata_flush_unlock(cache)

#include "metadata_cleaning_policy.h"
#include "metadata_eviction_policy.h"
#include "metadata_partition.h"
#include "metadata_hash.h"
#include "metadata_superblock.h"
#include "metadata_status.h"
#include "metadata_collision.h"
#include "metadata_core.h"
#include "metadata_misc.h"

#define INVALID 0
#define VALID 1
#define CLEAN 2
#define DIRTY 3

/**
 * @brief Initialize metadata
 *
 * @param cache - Cache instance
 * @param cache_line_size Cache line size
 * @return 0 - Operation success otherwise failure
 */
int ocf_metadata_init(struct ocf_cache *cache,
		ocf_cache_line_size_t cache_line_size);

/**
 * @brief Initialize per-cacheline metadata
 *
 * @param cache - Cache instance
 * @param device_size - Device size in bytes
 * @param cache_line_size Cache line size
 * @return 0 - Operation success otherwise failure
 */
int ocf_metadata_init_variable_size(struct ocf_cache *cache,
		uint64_t device_size, ocf_cache_line_size_t cache_line_size,
		ocf_metadata_layout_t layout);

/**
 * @brief Initialize collision table
 *
 * @param cache - Cache instance
 */
void ocf_metadata_init_freelist_partition(struct ocf_cache *cache);

/**
 * @brief Initialize hash table
 *
 * @param cache - Cache instance
 */
void ocf_metadata_init_hash_table(struct ocf_cache *cache);

/**
 * @brief De-Initialize metadata
 *
 * @param cache - Cache instance
 */
void ocf_metadata_deinit(struct ocf_cache *cache);

/**
 * @brief De-Initialize per-cacheline metadata
 *
 * @param cache - Cache instance
 */
void ocf_metadata_deinit_variable_size(struct ocf_cache *cache);

/**
 * @brief Get memory footprint
 *
 * @param cache - Cache instance
 * @return 0 - memory footprint
 */
size_t ocf_metadata_size_of(struct ocf_cache *cache);

/**
 * @brief Handle metadata error
 *
 * @param cache - Cache instance
 */
void ocf_metadata_error(struct ocf_cache *cache);

/**
 * @brief Get amount of cache lines
 *
 * @param cache - Cache instance
 * @return Amount of cache lines (cache device lines - metadata space)
 */
ocf_cache_line_t
ocf_metadata_get_cachelines_count(struct ocf_cache *cache);

/**
 * @brief Get amount of pages required for metadata
 *
 * @param cache - Cache instance
 * @return Pages required for store metadata on cache device
 */
ocf_cache_line_t ocf_metadata_get_pages_count(struct ocf_cache *cache);

/**
 * @brief Flush metadata
 *
 * @param cache
 * @return 0 - Operation success otherwise failure
 */
int ocf_metadata_flush_all(struct ocf_cache *cache);


/**
 * @brief Flush metadata for specified cache line
 *
 * @param[in] cache - Cache instance
 * @param[in] line - cache line which to be flushed
 */
void ocf_metadata_flush(struct ocf_cache *cache, ocf_cache_line_t line);

/**
 * @brief Mark specified cache line to be flushed
 *
 * @param[in] cache - Cache instance
 * @param[in] line - cache line which to be flushed
 */
void ocf_metadata_flush_mark(struct ocf_cache *cache, struct ocf_request *req,
		uint32_t map_idx, int to_state, uint8_t start, uint8_t stop);

/**
 * @brief Flush marked cache lines asynchronously
 *
 * @param cache - Cache instance
 * @param queue - I/O queue to which metadata flush should be submitted
 * @param remaining - request remaining
 * @param complete - flushing request callback
 * @param context - context that will be passed into callback
 */
void ocf_metadata_flush_do_asynch(struct ocf_cache *cache,
		struct ocf_request *req, ocf_req_end_t complete);

/**
 * @brief Load metadata
 *
 * @param cache - Cache instance
 * @return 0 - Operation success otherwise failure
 */
int ocf_metadata_load_all(struct ocf_cache *cache);

/**
 * @brief Load metadata required for recovery procedure
 *
 * @param cache Cache instance
 * @return 0 - Operation success otherwise failure
 */
int ocf_metadata_load_recovery(struct ocf_cache *cache);

/*
 * NOTE Hash table is specific for hash table metadata service implementation
 * and should be used internally by metadata service.
 * At the moment there is no high level metadata interface because of that
 * temporary defined in this file.
 */

static inline ocf_cache_line_t
ocf_metadata_get_hash(struct ocf_cache *cache, ocf_cache_line_t index)
{
	return cache->metadata.iface.get_hash(cache, index);
}

static inline void ocf_metadata_set_hash(struct ocf_cache *cache,
		ocf_cache_line_t index, ocf_cache_line_t line)
{
	cache->metadata.iface.set_hash(cache, index, line);
}

static inline void ocf_metadata_flush_hash(struct ocf_cache *cache,
		ocf_cache_line_t index)
{
	cache->metadata.iface.flush_hash(cache, index);
}

static inline ocf_cache_line_t ocf_metadata_entries_hash(
		struct ocf_cache *cache)
{
	return cache->metadata.iface.entries_hash(cache);
}

int ocf_metadata_load_properties(ocf_volume_t cache_volume,
		ocf_cache_line_size_t *line_size,
		ocf_metadata_layout_t *layout,
		ocf_cache_mode_t *cache_mode,
		enum ocf_metadata_shutdown_status *shutdown_status,
		uint8_t *dirty_flushed);

/**
 * @brief Validate cache line size
 *
 * @param size Cache line size
 * @return true - cache line size is valid, false - cache line is invalid
 */
static inline bool ocf_metadata_line_size_is_valid(uint32_t size)
{
	switch (size) {
	case 4 * KiB:
	case 8 * KiB:
	case 16 * KiB:
	case 32 * KiB:
	case 64 * KiB:
		return true;
	default:
		return false;
	}
}

#endif /* METADATA_H_ */
