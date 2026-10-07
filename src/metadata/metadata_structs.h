/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2025 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_STRUCTS_H__
#define __METADATA_STRUCTS_H__

#include "metadata_common.h"
#include "../ocf_space.h"
#include "../cleaning/cleaning.h"
#include "../ocf_request.h"
#include "metadata_superblock.h"


/**
 * @file metadata_priv.h
 * @brief Metadata private structures
 */

/**
 * @brief Metadata control structure
 */
struct ocf_metadata {
	void *priv;
		/*!< Private data of metadata service interface */

	ocf_cache_line_size_t line_size;
		/*!< Cache line size */

	bool is_volatile;
		/*!< true if metadata used in volatile mode (RAM only) */

	ocf_cache_line_t line_count;
		/*!< Number of collision table entries */

	uint32_t hash_entries;
		/*!< Number of hash table entries */

	uint64_t data_offset;
		/*!< Start of cache data area on cache device (in bytes) */
};

/**
 * @brief Get number of cache lines (collision table entries)
 */
static inline ocf_cache_line_t ocf_metadata_line_count(
		const struct ocf_metadata *metadata)
{
	return metadata->line_count;
}

/**
 * @brief Get cache line index used as list terminator / unmapped marker
 */
static inline ocf_cache_line_t ocf_metadata_terminator_line(
		const struct ocf_metadata *metadata)
{
	return metadata->line_count;
}

/**
 * @brief Get number of hash table entries
 */
static inline uint32_t ocf_metadata_hash_entries(
		const struct ocf_metadata *metadata)
{
	return metadata->hash_entries;
}

/**
 * @brief Get offset of cache data area on cache device (in bytes)
 */
static inline uint64_t ocf_metadata_data_offset(
		const struct ocf_metadata *metadata)
{
	return metadata->data_offset;
}

#endif /* __METADATA_STRUCTS_H__ */
