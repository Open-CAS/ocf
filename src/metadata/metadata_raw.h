/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_RAW_H__
#define __METADATA_RAW_H__

#include "metadata_common.h"
#include "metadata_segment_id.h"
#include "metadata_layout.h"
#include "../concurrency/ocf_mio_concurrency.h"

/**
 * @file metadata_raw.h
 * @brief Metadata RAW container implementation
 */

/**
 * @brief Metadata raw type
 */
enum ocf_metadata_raw_type {
	/**
	 * @brief Default implementation with support of
	 * flushing to/landing from SSD
	 */
	metadata_raw_type_ram = 0,

	/**
	 * @brief Dynamic implementation, elements are allocated when first
	 * time called
	 */
	metadata_raw_type_dynamic,

	/**
	 * @brief This containers does not flush metadata on SSD and does not
	 * Support loading from SSD
	 */
	metadata_raw_type_volatile,

	/**
	 * @brief Implementation for atomic device used as cache
	 */
	metadata_raw_type_atomic,

	metadata_raw_type_max, /*!<  MAX */
	metadata_raw_type_min = metadata_raw_type_ram /*!<  MAX */
};

struct ocf_metadata_raw;

/**
 * @brief Container page lock/unlock callback
 */

/**
 * @brief RAW instance descriptor
 */
struct ocf_metadata_raw {
	/**
	 * @name Metadata and RAW types
	 */
	enum ocf_metadata_segment_id metadata_segment; /*!< Metadata segment */
	enum ocf_metadata_raw_type raw_type; /*!< RAW implementation type */

	/**
	 * @name Metadata elements description and location on cache device
	 */
	const struct ocf_metadata_segment_layout *layout;
		/*!< Segment layout */

	const struct raw_iface *iface; /*!< RAW container interface*/

	/**
	 * @name Private RAW elements
	 */
	void *mem_pool; /*!< Private memory pool*/

	size_t mem_pool_limit; /*! Current memory pool size (limit) */

	void *priv; /*!< Private data - context */

	env_rwsem *page_locks; /*!< Page locks (NULL if not used) */

	struct ocf_alock *mio_conc;
};

/**
 * RAW container interface
 */
struct raw_iface {
	int (*init)(ocf_cache_t cache, bool flush_asynch,
			struct ocf_metadata_raw *raw);

	int (*deinit)(ocf_cache_t cache,
			struct ocf_metadata_raw *raw);

	size_t (*size_of)(ocf_cache_t cache,
			struct ocf_metadata_raw *raw);

	/**
	 * @brief Return size which metadata take on cache device
	 *
	 * @param raw RAW container of metadata
	 *
	 * @return Number of pages (4 kiB) on cache device
	 */
	uint32_t (*size_on_ssd)(struct ocf_metadata_raw *raw);

	uint32_t (*checksum)(ocf_cache_t cache,
			struct ocf_metadata_raw *raw);

	uint32_t (*page)(struct ocf_metadata_raw *raw, uint32_t entry);

	void* (*wr_access)(ocf_cache_t cache, struct ocf_metadata_raw *raw,
			uint32_t entry);

	const void* (*rd_access)(ocf_cache_t cache,
			struct ocf_metadata_raw *raw, uint32_t entry);

	int (*update)(ocf_cache_t cache, struct ocf_metadata_raw *raw,
			ctx_data_t *data, uint64_t page, uint64_t count);

	void (*zero)(ocf_cache_t cache, struct ocf_metadata_raw *raw,
			ocf_metadata_end_t cmpl, void *priv);

	void (*load_all)(ocf_cache_t cache, struct ocf_metadata_raw *raw,
			ocf_metadata_end_t cmpl, void *priv,
			unsigned flapping_idx);

	void (*flush_all)(ocf_cache_t cache, struct ocf_metadata_raw *raw,
			ocf_metadata_end_t cmpl, void *priv,
			unsigned flapping_idx);

	void (*flush_mark)(ocf_cache_t cache, struct ocf_request *req,
			uint32_t map_idx, int to_state, uint8_t start,
			uint8_t stop);

	int (*flush_do_asynch)(ocf_cache_t cache, struct ocf_request *req,
			struct ocf_metadata_raw *raw, ocf_req_end_t complete);
};

/**
 * @brief Initialize RAW instance
 *
 * @param cache - Cache instance
 * @param flush_asynch - RAW is flushed asynchronously (flush_do_asynch),
 *		concurrently with modifications of its content
 * @param raw - RAW descriptor
 * @return 0 - Operation success, otherwise error
 */
int ocf_metadata_raw_init(ocf_cache_t cache, bool flush_asynch,
		struct ocf_metadata_raw *raw);

/**
 * @brief De-Initialize RAW instance
 *
 * @param cache - Cache instance
 * @param raw - RAW descriptor
 * @return 0 - Operation success, otherwise error
 */
int ocf_metadata_raw_deinit(ocf_cache_t cache,
		struct ocf_metadata_raw *raw);

/**
 * @brief Get memory footprint
 *
 * @param cache Cache instance
 * @param raw RAW descriptor
 * @return Memory footprint
 */
static inline size_t ocf_metadata_raw_size_of(ocf_cache_t cache,
		struct ocf_metadata_raw *raw)
{
	if (!raw->iface)
		return 0;

	return raw->iface->size_of(cache, raw);
}

/**
 * @brief Get SSD footprint
 *
 * @param raw - RAW descriptor
 * @return Size on SSD
 */
size_t ocf_metadata_raw_size_on_ssd(struct ocf_metadata_raw* raw);

/**
 * @brief Calculate metadata checksum
 *
 * @param cache - Cache instance
 * @param raw - RAW descriptor
 * @return Checksum
 */
static inline uint32_t ocf_metadata_raw_checksum(struct ocf_cache* cache,
		struct ocf_metadata_raw* raw)
{
	return raw->iface->checksum(cache, raw);
}

/**
 * @brief Calculate entry page index
 *
 * @param raw - RAW descriptor
 * @param entry - Entry number
 * @return Page index
 */
static inline uint32_t ocf_metadata_raw_page(struct ocf_metadata_raw* raw,
		uint32_t entry)
{
	return raw->iface->page(raw, entry);
}

/**
 * @brief Lock RAW page for modification of its content
 *
 * Multiple entries within the same page can be modified concurrently,
 * as modifications of the particular entries are synchronized by
 * higher level locks.
 *
 * @param raw - RAW descriptor
 * @param page - Page number
 */
static inline void ocf_metadata_raw_page_lock_modify(
		struct ocf_metadata_raw *raw, uint32_t page)
{
	if (raw->page_locks)
		env_rwsem_down_read(&raw->page_locks[page]);
}

/**
 * @brief Unlock RAW page locked for modification of its content
 *
 * @param raw - RAW descriptor
 * @param page - Page number
 */
static inline void ocf_metadata_raw_page_unlock_modify(
		struct ocf_metadata_raw *raw, uint32_t page)
{
	if (raw->page_locks)
		env_rwsem_up_read(&raw->page_locks[page]);
}

/**
 * @brief Lock RAW page for copying consistent snapshot of its content
 *
 * @param raw - RAW descriptor
 * @param page - Page number
 */
static inline void ocf_metadata_raw_page_lock_copy(
		struct ocf_metadata_raw *raw, uint32_t page)
{
	if (raw->page_locks)
		env_rwsem_down_write(&raw->page_locks[page]);
}

/**
 * @brief Unlock RAW page locked for copying
 *
 * @param raw - RAW descriptor
 * @param page - Page number
 */
static inline void ocf_metadata_raw_page_unlock_copy(
		struct ocf_metadata_raw *raw, uint32_t page)
{
	if (raw->page_locks)
		env_rwsem_up_write(&raw->page_locks[page]);
}

/**
 * @brief Access specified element of metadata directly
 *
 * @param cache - Cache instance
 * @param raw - RAW descriptor
 * @param entry - Entry to be get
 * @param data - Data where metadata entry will be copied into
 * @return 0 - Point to accessed data, in case of error NULL
 */
static inline void *ocf_metadata_raw_wr_access(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, uint32_t entry)
{
	return raw->iface->wr_access(cache, raw, entry);
}

/**
 * @brief Access specified element of metadata directly
 *
 * @param cache - Cache instance
 * @param raw - RAW descriptor
 * @param entry - Entry to be get
 * @return 0 - Point to accessed data, in case of error NULL
 */
static inline const void *ocf_metadata_raw_rd_access( ocf_cache_t cache,
		struct ocf_metadata_raw *raw, uint32_t entry)
{
	return raw->iface->rd_access(cache, raw, entry);
}

/**
 * @brief Update metadata based on cache device I/O
 *
 * @param cache - Cache instance
 * @param raw - RAW descriptor
 * @param data - Data buffer containing metadata pages
 * @param page - First metadata page
 * @param count - Number of metadata pages
 * @return 0 - Operation success, otherwise error
 */
static inline int ocf_metadata_raw_update(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, ctx_data_t *data,
		uint64_t page, uint64_t count)
{
	return raw->iface->update(cache, raw, data, page, count);
}

/**
 * @brief Zero metadata
 * @details NOTE: this is fo management purposes only, no synchronization with
 * 		I/O is guarangeed
 *
 * @param cache - Cache instance
 * @param raw - RAW descriptor
 * @param cmpl - completion callback
 * @param priv - completion callback private context
 */
static inline void ocf_metadata_raw_zero(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, ocf_metadata_end_t cmpl,
		void *priv)
{
	raw->iface->zero(cache, raw, cmpl, priv);
}

/**
 * @brief Load all entries from SSD cache (cahce cache)
 *
 * @param cache - Cache instance
 * @param raw - RAW descriptor
 * @param cmpl - Completion callback
 * @param priv - Completion callback context
 * @param flapping_idx - Index of flapping segment version
 */
static inline void ocf_metadata_raw_load_all(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, ocf_metadata_end_t cmpl,
		void *priv, unsigned flapping_idx)
{
	raw->iface->load_all(cache, raw, cmpl, priv, flapping_idx);
}

/**
 * @brief Flush all entries for into SSD cache (cahce cache)
 *
 * @param cache - Cache instance
 * @param raw - RAW descriptor
 * @param cmpl - Completion callback
 * @param priv - Completion callback context
 * @param flapping_idx - Index of flapping segment version
 */
static inline void ocf_metadata_raw_flush_all(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, ocf_metadata_end_t cmpl,
		void *priv, unsigned flapping_idx)
{
	raw->iface->flush_all(cache, raw, cmpl, priv, flapping_idx);
}


static inline void ocf_metadata_raw_flush_mark(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, struct ocf_request *req,
		uint32_t map_idx, int to_state, uint8_t start, uint8_t stop)
{
	raw->iface->flush_mark(cache, req, map_idx, to_state, start, stop);
}

static inline int ocf_metadata_raw_flush_do_asynch(ocf_cache_t cache,
		struct ocf_request *req, struct ocf_metadata_raw *raw,
		ocf_req_end_t complete)
{
	return raw->iface->flush_do_asynch(cache, req, raw, complete);
}

/*
 * Check if line is valid for specified RAW descriptor
 */
static inline bool _raw_is_valid(struct ocf_metadata_raw *raw, uint32_t entry)
{
	if (unlikely(!raw))
		return false;

	if (unlikely(entry >= raw->layout->entries))
		return false;

	return true;
}

#define MAX_STACK_TAB_SIZE 32

int _raw_ram_flush_do_page_cmp(const void *item1, const void *item2);

static inline void *ocf_metadata_raw_get_mem(struct ocf_metadata_raw *raw)
{
	return raw->mem_pool;
}

#endif /* __METADATA_RAW_H__ */
