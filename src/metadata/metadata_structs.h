/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_STRUCTS_H__
#define __METADATA_STRUCTS_H__

#include "metadata_common.h"
#include "../eviction/eviction.h"
#include "../cleaning/cleaning.h"
#include "../ocf_request.h"


/**
 * @file metadata_priv.h
 * @brief Metadata private structures
 */

/**
 * @brief Metadata shutdown status
 */
enum ocf_metadata_shutdown_status {
	ocf_metadata_clean_shutdown = 1, /*!< OCF shutdown graceful*/
	ocf_metadata_dirty_shutdown = 0, /*!< Dirty OCF shutdown*/
	ocf_metadata_detached = 2, /*!< Cache device detached */
};

/**
 * @brief Query cores completion callback
 *
 * @param priv - Caller private data
 * @param error - Operation error status
 * @param num_cores - Number of cores in metadata
 */
typedef void (*ocf_metadata_query_cores_end_t)(void *priv, int error,
		unsigned int num_cores);

struct ocf_cache_line_settings {
	ocf_cache_line_size_t size;
	uint64_t sector_count;
	uint64_t sector_start;
	uint64_t sector_end;
};


#define OCF_METADATA_GLOBAL_LOCK_IDX_BITS 2
#define OCF_NUM_GLOBAL_META_LOCKS (1 << (OCF_METADATA_GLOBAL_LOCK_IDX_BITS))

struct ocf_metadata_global_lock {
	env_rwsem sem;
} __attribute__((aligned(64)));

struct ocf_metadata_lock
{
	struct ocf_metadata_global_lock global[OCF_NUM_GLOBAL_META_LOCKS];
			/*!< global metadata lock (GML) */
	env_rwlock eviction[OCF_NUM_EVICTION_LISTS]; /*!< Fast lock for eviction policy */
	env_rwsem *hash; /*!< Hash bucket locks */
	env_rwsem *collision_pages; /*!< Collision table page locks */
	env_spinlock partition[OCF_IO_CLASS_MAX]; /* partition lock */
	uint32_t num_hash_entries;  /*!< Hash bucket count */
	uint32_t num_collision_pages; /*!< Collision table page count */
	ocf_cache_t cache;  /*!< Parent cache object */
};

/**
 * @brief Metadata control structure
 */
struct ocf_metadata {
	ocf_metadata_layout_t layout;
		/*!< Per-cacheline metadata layout */

	void *priv;
		/*!< Private data of metadata service interface */

	const struct ocf_cache_line_settings settings;
		/*!< Cache line configuration */

	bool is_volatile;
		/*!< true if metadata used in volatile mode (RAM only) */

	struct ocf_metadata_lock lock;
};

#endif /* __METADATA_STRUCTS_H__ */
