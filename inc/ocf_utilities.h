/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */


#ifndef __OCF_UTILITIES_H__
#define __OCF_UTILITIES_H__

/**
 * @file
 * @brief OCF memory pool reference
 */

struct ocf_mpool;

/**
 * @brief Create OCF memory pool
 *
 * @param cache OCF cache instance
 * @param size Size of particular item
 * @param hdr_size Header size before array of items
 * @param flags Allocation flags
 * @param mpool_max Maximal allocator size (power of two)
 * @param fmt_name Format name of allocator
 * @param ... Format parameters
 *
 * @return OCF memory pool reference
 */
struct ocf_mpool *ocf_mpool_create(struct ocf_cache *cache,
		uint32_t hdr_size, uint32_t size, int flags, int mpool_max,
		const char *name_perfix);

/**
 * @brief Destroy existing memory pool
 *
 * @param mpool memory pool
 */
void ocf_mpool_destroy(struct ocf_mpool *mpool);

/**
 * @brief Allocate new items of memory pool
 *
 * @note Allocation based on ATOMIC memory pool and this function can be called
 * when IRQ disable
 *
 * @param mpool OCF memory pool reference
 * @param count Count of elements to be allocated
 *
 * @return Pointer to the new items
 */
void *ocf_mpool_new(struct ocf_mpool *mpool, uint32_t count);

/**
 * @brief Allocate new items of memory pool with specified allocation flag
 *
 * @param mpool OCF memory pool reference
 * @param count Count of elements to be allocated
 * @param flags Kernel allocation falgs
 *
 * @return Pointer to the new items
 */
void *ocf_mpool_new_f(struct ocf_mpool *mpool, uint32_t count, int flags);

/**
 * @brief Free existing items of memory pool
 *
 * @param mpool OCF memory pool reference
 * @param items Items to be freed
 * @param count - Count of elements to be free
 */
void ocf_mpool_del(struct ocf_mpool *mpool, void *items, uint32_t count);

#endif /* __OCF_UTILITIES_H__ */
