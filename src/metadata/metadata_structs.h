/*
 * Copyright(c) 2012-2020 Intel Corporation
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

/**
 * OCF Metadata interface
 */
struct ocf_metadata_iface {
	/**
	 * @brief Initialize metadata
	 *
	 * @param cache - Cache instance
	 * @param cache_line_size - Cache line size
	 * @return 0 - Operation success otherwise failure
	 */
	int (*init)(struct ocf_cache *cache,
			ocf_cache_line_size_t cache_line_size);

	/**
	 * @brief Initialize variable size metadata sections
	 *
	 * @param cache - Cache instance
	 * @param device_size - Cache size in bytes
	 * @param cache_line_size - Cache line size
	 * @param layout Metadata layout
	 * @return 0 - Operation success otherwise failure
	 */
	int (*init_variable_size)(struct ocf_cache *cache, uint64_t device_size,
			ocf_cache_line_size_t cache_line_size,
			ocf_metadata_layout_t layout);

	/**
	 * @brief Query metadata for added cores
	 *
	 * @param[in] owner - OCF context
	 * @param[in] volume - volume to probe
	 * @param[in,out] uuid - array of uuids
	 * @param[in] count - size of uuid array
	 * @param[in] cmpl - completion callback
	 * @param[in] priv - completion private data
	 */
	void (*query_cores)(ocf_ctx_t owner, ocf_volume_t volume,
		struct ocf_volume_uuid *uuid, uint32_t count,
		ocf_metadata_query_cores_end_t cmpl, void *priv);


	/**
	 * @brief Per-cacheline metadata layout
	 */
	ocf_metadata_layout_t layout;

	/**
	 * @brief Initialize hash table
	 *
	 * @param cache - Cache instance
	 */
	void (*init_hash_table)(struct ocf_cache *cache);

	/**
	 * @brief Initialize collision table
	 *
	 * @param cache - Cache instance
	 */
	void (*init_collision)(struct ocf_cache *cache);

	/**
	 * @brief De-Initialize metadata
	 *
	 * @param cache - Cache instance
	 */
	void (*deinit)(struct ocf_cache *cache);

	/**
	 * @brief De-Initialize variable size metadata segments
	 *
	 * @param cache - Cache instance
	 */
	void (*deinit_variable_size)(struct ocf_cache *cache);

	/**
	 * @brief Get memory footprint
	 *
	 * @param cache - Cache instance
	 * @return 0 - memory footprint
	 */
	size_t (*size_of)(struct ocf_cache *cache);

	/**
	 * @brief Get amount of pages required for metadata
	 *
	 * @param cache - Cache instance
	 * @return Pages required for store metadata on cache device
	 */
	ocf_cache_line_t (*pages)(struct ocf_cache *cache);

	/**
	 * @brief Get amount of cache lines
	 *
	 * @param cache - Cache instance
	 * @return Amount of cache lines (cache device lines - metadata space)
	 */
	ocf_cache_line_t (*cachelines)(struct ocf_cache *cache);

	/**
	 * @brief Load metadata from cache device
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] cmpl - Completion callback
	 * @param[in] priv - Completion callback context
	 */
	void (*load_all)(ocf_cache_t cache,
			ocf_metadata_end_t cmpl, void *priv);

	/**
	 * @brief Load metadata from recovery procedure
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] cmpl - Completion callback
	 * @param[in] priv - Completion callback context
	 */
	void (*load_recovery)(ocf_cache_t cache,
			ocf_metadata_end_t cmpl, void *priv);

	/**
	 * @brief Flush metadata into cahce cache
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] cmpl - Completion callback
	 * @param[in] priv - Completion callback context
	 */
	void (*flush_all)(ocf_cache_t cache,
			ocf_metadata_end_t cmpl, void *priv);

	/**
	 * @brief Mark specified cache line to be flushed
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] line - cache line which to be flushed
	 */
	void (*flush_mark)(struct ocf_cache *cache, struct ocf_request *req,
			uint32_t map_idx, int to_state, uint8_t start,
			uint8_t stop);

	/**
	 * @brief Flush marked cache lines asynchronously
	 *
	 * @param cache - Cache instance
	 * @param queue - I/O queue to which metadata flush should be submitted
	 * @param remaining - request remaining
	 * @param complete - flushing request callback
	 * @param context - context that will be passed into callback
	 */
	void (*flush_do_asynch)(struct ocf_cache *cache,
			struct ocf_request *req, ocf_req_end_t complete);


	/* TODO Provide documentation below */

	enum ocf_metadata_shutdown_status (*get_shutdown_status)(
			struct ocf_cache *cache);

	void (*set_shutdown_status)(ocf_cache_t cache,
			enum ocf_metadata_shutdown_status shutdown_status,
			ocf_metadata_end_t cmpl, void *priv);

	void (*load_superblock)(ocf_cache_t cache,
			ocf_metadata_end_t cmpl, void *priv);

	void (*flush_superblock)(ocf_cache_t cache,
			ocf_metadata_end_t cmpl, void *priv);

	uint64_t (*get_reserved_lba)(struct ocf_cache *cache);

	/**
	 * @brief Get eviction policy
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] line - cache line for which eviction policy is requested
	 * @return eviction policy metadata
	 */
	union eviction_policy_meta *(*get_eviction_policy)(
			struct ocf_cache *cache, ocf_cache_line_t line);

	/**
	 * @brief Get cleaning policy
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] line - cache line for which cleaning policy is requested
	 * @return cleaning_policy metadata
	 */
	struct cleaning_policy_meta *(*get_cleaning_policy)(
			struct ocf_cache *cache, ocf_cache_line_t line);

	/**
	 * @brief Get hash table for specified index
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] index - Hash table index
	 * @return Cache line value under specified hash table index
	 */
	 ocf_cache_line_t (*get_hash)(struct ocf_cache *cache,
			ocf_cache_line_t index);

	/**
	 * @brief Set hash table value for specified index
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] index - Hash table index
	 * @param[in] line - Cache line value to be set under specified hash
	 * table index
	 */
	void (*set_hash)(struct ocf_cache *cache,
			ocf_cache_line_t index, ocf_cache_line_t line);

	/**
	 * @brief Get hash table entries
	 *
	 * @param[in] cache - Cache instance
	 * @return Hash table entries
	 */
	ocf_cache_line_t (*entries_hash)(struct ocf_cache *cache);

	/* TODO Provide documentation below */
	void (*set_core_info)(struct ocf_cache *cache,
			ocf_cache_line_t line, ocf_core_id_t core_id,
			uint64_t core_sector);

	void (*get_core_info)(struct ocf_cache *cache,
			ocf_cache_line_t line, ocf_core_id_t *core_id,
			uint64_t *core_sector);

	ocf_core_id_t (*get_core_id)(struct ocf_cache *cache,
			ocf_cache_line_t line);

	void (*get_core_and_part_id)(struct ocf_cache *cache,
			ocf_cache_line_t line, ocf_core_id_t *core_id,
			ocf_part_id_t *part_id);

	struct ocf_metadata_uuid *(*get_core_uuid)(
			struct ocf_cache *cache, ocf_core_id_t core_id);

	void (*set_collision_info)(struct ocf_cache *cache,
			ocf_cache_line_t line, ocf_cache_line_t next,
			ocf_cache_line_t prev);

	void (*get_collision_info)(struct ocf_cache *cache,
				ocf_cache_line_t line, ocf_cache_line_t *next,
				ocf_cache_line_t *prev);

	void (*set_collision_next)(struct ocf_cache *cache,
				ocf_cache_line_t line, ocf_cache_line_t next);

	void (*set_collision_prev)(struct ocf_cache *cache,
				ocf_cache_line_t line, ocf_cache_line_t prev);

	void (*start_collision_shared_access)(struct ocf_cache *cache,
			ocf_cache_line_t line);

	void (*end_collision_shared_access)(struct ocf_cache *cache,
			ocf_cache_line_t line);

	void (*get_partition_info)(struct ocf_cache *cache,
			ocf_cache_line_t line, ocf_part_id_t *part_id,
			ocf_cache_line_t *next_line,
			ocf_cache_line_t *prev_line);

	void (*set_partition_next)(struct ocf_cache *cache,
			ocf_cache_line_t line, ocf_cache_line_t next_line);

	void (*set_partition_prev)(struct ocf_cache *cache,
			ocf_cache_line_t line, ocf_cache_line_t prev_line);

	void (*set_partition_info)(struct ocf_cache *cache,
			ocf_cache_line_t line, ocf_part_id_t part_id,
			ocf_cache_line_t next_line, ocf_cache_line_t prev_line);

	const struct ocf_metadata_status*
	(*rd_status_access)(struct ocf_cache *cache,
			ocf_cache_line_t line);

	struct ocf_metadata_status*
	(*wr_status_access)(struct ocf_cache *cache,
			ocf_cache_line_t line);
};

struct ocf_cache_line_settings {
	ocf_cache_line_size_t size;
	uint64_t sector_count;
	uint64_t sector_start;
	uint64_t sector_end;
};

struct ocf_metadata_lock
{
	env_rwsem global; /*!< global metadata lock (GML) */
	env_rwlock status; /*!< Fast lock for status bits */
	env_spinlock eviction[OCF_NUM_EVICTION_LISTS]; /*!< Fast lock for eviction policy */
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
	const struct ocf_metadata_iface iface;
		/*!< Metadata service interface */

	void *priv;
		/*!< Private data of metadata service interface */

	const struct ocf_cache_line_settings settings;
		/*!< Cache line configuration */

	bool is_volatile;
		/*!< true if metadata used in volatile mode (RAM only) */

	struct ocf_metadata_lock lock;
};

#endif /* __METADATA_STRUCTS_H__ */
