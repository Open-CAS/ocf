/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_STRUCTS_H__
#define __METADATA_STRUCTS_H__

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

/*
 * Metadata cache line location on pages interface
 */
struct ocf_metadata_layout_iface {

	/**
	 * @brief Initialize freelist partition
	 *
	 * @param cache - Cache instance
	 */

	void (*init_freelist)(struct ocf_cache *cache);

	/**
	 * This function is mapping collision index to appropriate cache line
	 * (logical cache line to physical one mapping).
	 *
	 * It is necessary because we want to generate sequential workload with
	 * data to cache device.
	 *	Our collision list, for example, looks:
	 *			0 3 6 9
	 *			1 4 7 10
	 *			2 5 8
	 *	All collision index in each column is on the same page
	 *	on cache device. We don't want send request x times to the same
	 *	page. To don't do it we use collision index by row, but in this
	 *	case we can't use collision index directly as cache line,
	 *	because we will generate non sequential workload (we will write
	 *	pages: 0 -> 3 -> 6 ...). To map collision index in correct way
	 *	we use this function.
	 *
	 *	After use this function, collision index in the above array
	 *	corresponds with below cache line:
	 *			0 1 2 3
	 *			4 5 6 7
	 *			8 9 10
	 *
	 * @param cache - cache instance
	 * @param idx - index in collision list
	 * @return mapped cache line
	 */
	ocf_cache_line_t (*lg2phy)(struct ocf_cache *cache,
			ocf_cache_line_t coll_idx);

	/**
	 * @brief Map physical cache line on cache device to logical one
	 * @note This function is the inverse of map_coll_idx_to_cache_line
	 *
	 * @param cache Cache instance
	 * @param phy Physical cache line of cache device
	 * @return Logical cache line
	 */
	ocf_cache_line_t (*phy2lg)(struct ocf_cache *cache,
			ocf_cache_line_t phy);
};

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
	 * @brief Metadata cache line location on pages interface
	 */
	const struct ocf_metadata_layout_iface *layout_iface;

	/**
	 * @brief Initialize hash table
	 *
	 * @param cache - Cache instance
	 */
	void (*init_hash_table)(struct ocf_cache *cache);

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
	 * @return 0 - Operation success otherwise failure
	 */
	int (*load_all)(struct ocf_cache *cache);

	/**
	 * @brief Load metadata from recovery procedure
	 * recovery
	 * @param[in] cache - Cache instance
	 * @return 0 - Operation success otherwise failure
	 */
	int (*load_recovery)(struct ocf_cache *cache);

	/**
	 * @brief Flush metadata into cahce cache
	 *
	 * @param[in] cache - Cache instance
	 * @return 0 - Operation success otherwise failure
	 */
	int (*flush_all)(struct ocf_cache *cache);

	/**
	 * @brief Flush metadata for specified cache line
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] line - cache line which to be flushed
	 */
	void (*flush)(struct ocf_cache *cache, ocf_cache_line_t line);

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

	int (*set_shutdown_status)(struct ocf_cache *cache,
			enum ocf_metadata_shutdown_status shutdown_status);

	int (*load_superblock)(struct ocf_cache *cache);

	int (*flush_superblock)(struct ocf_cache *cache);

	uint64_t (*get_reserved_lba)(struct ocf_cache *cache);

	/**
	 * @brief Get eviction policy
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] line - cache line for which eviction policy is requested
	 * @param[out] eviction_policy - Eviction policy
	 */
	void (*get_eviction_policy)(struct ocf_cache *cache,
			ocf_cache_line_t line,
			union eviction_policy_meta *eviction_policy);

	/**
	 * @brief Set eviction policy
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] line - Eviction policy values which will be stored in
	 * metadata service
	 * @param[out] eviction_policy - Eviction policy
	 */
	void (*set_eviction_policy)(struct ocf_cache *cache,
			ocf_cache_line_t line,
			union eviction_policy_meta *eviction_policy);

	/**
	 * @brief Flush eviction policy for given cache line
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] line - Cache line for which flushing has to be performed
	 */
	void (*flush_eviction_policy)(struct ocf_cache *cache,
			ocf_cache_line_t line);


	/**
	 * @brief Get cleaning policy
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] line - cache line for which cleaning policy is requested
	 * @param[out] cleaning_policy - Cleaning policy
	 */
	 void (*get_cleaning_policy)(struct ocf_cache *cache,
			ocf_cache_line_t line,
			struct cleaning_policy_meta *cleaning_policy);

	/**
	 * @brief Set cleaning policy
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] line
	 * @param[in] cleaning_policy - Cleaning policy values which will be
	 * stored in metadata service
	 */
	void (*set_cleaning_policy)(struct ocf_cache *cache,
			ocf_cache_line_t line,
			struct cleaning_policy_meta *cleaning_policy);

	/**
	 * @brief Flush cleaning policy for given cache line
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] line - Cache line for which flushing has to be performed
	 */
	void (*flush_cleaning_policy)(struct ocf_cache *cache,
			ocf_cache_line_t line);

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
	 * @brief Flush has table for specified index
	 *
	 * @param[in] cache - Cache instance
	 * @param[in] index - Hash table index
	 */
	void (*flush_hash)(struct ocf_cache *cache,
			ocf_cache_line_t index);

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

	uint64_t (*get_core_sector)(struct ocf_cache *cache,
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

	ocf_cache_line_t (*get_collision_next)(struct ocf_cache *cache,
				ocf_cache_line_t line);

	ocf_cache_line_t (*get_collision_prev)(struct ocf_cache *cache,
					ocf_cache_line_t line);

	ocf_part_id_t (*get_partition_id)(struct ocf_cache *cache,
			ocf_cache_line_t line);

	ocf_cache_line_t (*get_partition_next)(struct ocf_cache *cache,
			ocf_cache_line_t line);

	ocf_cache_line_t (*get_partition_prev)(struct ocf_cache *cache,
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

	bool (*test_dirty)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);

	bool (*test_out_dirty)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);

	bool (*clear_dirty)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);

	bool (*set_dirty)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);

	bool (*test_and_set_dirty)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);

	bool (*test_and_clear_dirty)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);


	bool (*test_valid)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);

	bool (*test_out_valid)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);

	bool (*clear_valid)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);

	bool (*set_valid)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);

	bool (*test_and_set_valid)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);

	bool (*test_and_clear_valid)(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);
};

struct ocf_cache_line_settings {
	ocf_cache_line_size_t size;
	uint64_t sector_count;
	uint64_t sector_start;
	uint64_t sector_end;
};

/**
 * @brief Metadata control structure
 */
struct ocf_metadata {
	const struct ocf_metadata_iface iface;
		/*!< Metadata service interface */

	void *iface_priv;
		/*!< Private data of metadata service interface */

	const struct ocf_cache_line_settings settings;
		/*!< Cache line configuration */

	bool is_volatile;
		/*!< true if metadata used in volatile mode (RAM only) */

	struct {
		env_rwsem collision; /*!< lock for collision table */
		env_rwlock status; /*!< Fast lock for status bits */
		env_spinlock eviction; /*!< Fast lock for eviction policy */
	} lock;
};


#define OCF_METADATA_RD 0
#define OCF_METADATA_WR 1

#endif /* __METADATA_STRUCTS_H__ */
