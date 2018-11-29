/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_METADATA_H__
#define __OCF_METADATA_H__

/**
 * @file
 * @brief OCF metadata helper function
 *
 * Those functions can be used by data object implementation.
 */

/**
 * @brief Atomic metadata for extended sector
 *
 * @warning The size of this structure has to be equal 8 bytes
 */
struct ocf_atomic_metadata {
	/** Core line of core (in cache line size unit) which are cached */
	uint64_t core_line : 46;

	/** Core sequence number to which this line belongs to*/
	uint32_t core_seq_no : 16;

	/** Set bit indicates that given sector is valid (is cached) */
	uint32_t valid : 1;

	/** Set bit indicates that sector i dirty */
	uint32_t dirty : 1;
} __attribute__((packed));

#define OCF_ATOMIC_METADATA_SIZE	sizeof(struct ocf_atomic_metadata)

/**
 * @brief Get metadata entry (cache mapping) for specified sector of cache
 * device
 *
 * Metadata has sector granularity. It might be used by data object which
 * supports atomic writes - (write of data and metadata in one buffer)
 *
 * @param[in] cache OCF cache instance
 * @param[in] addr Sector address in bytes
 * @param[out] entry Metadata entry
 *
 * @retval 0 Metadata retrieved successfully
 * @retval Non-zero Error
 */
int ocf_metadata_get_atomic_entry(ocf_cache_t cache, uint64_t addr,
		struct ocf_atomic_metadata *entry);

/**
 * @brief Probe cache device
 *
 * @param[in] ctx handle to object designating ocf context
 * @param[in] cache_obj Cache data object
 * @param[out] clean_shutdown Cache was graceful stopped
 * @param[out] cache_dirty Cache is dirty
 *
 * @retval 0 Probe successfully performed
 * @retval -ENODATA Cache has not been detected
 * @retval Non-zero ERROR
 */
int ocf_metadata_probe(ocf_ctx_t ctx, ocf_data_obj_t cache_obj,
		bool *clean_shutdown, bool *cache_dirty);

/**
 * @brief Check if sectors in cache line before given address are invalid
 *
 * It might be used by data object which supports
 * atomic writes - (write of data and metadata in one buffer)
 *
 * @param[in] cache OCF cache instance
 * @param[in] addr Sector address in bytes
 *
 * @retval 0 Not all sectors before given address are invalid
 * @retval Non-zero Number of sectors before given address
 */
int ocf_metadata_check_invalid_before(ocf_cache_t cache, uint64_t addr);

/**
 * @brief Check if sectors in cache line after given end address are invalid
 *
 * It might be used by data object which supports
 * atomic writes - (write of data and metadata in one buffer)
 *
 * @param[in] cache OCF cache instance
 * @param[in] addr Sector address in bytes
 * @param[in] bytes IO size in bytes
 *
 * @retval 0 Not all sectors after given end address are invalid
 * @retval Non-zero Number of sectors after given end address
 */
int ocf_metadata_check_invalid_after(ocf_cache_t cache, uint64_t addr,
		uint32_t bytes);

#endif /* __OCF_METADATA_H__ */
