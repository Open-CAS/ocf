/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef UTILS_RQ_H_
#define UTILS_RQ_H_

#include "../ocf_request.h"

/**
 * @file utils_rq.h
 * @brief OCF request allocation utilities
 */

struct ocf_rq_allocator;

/**
 * @brief Initialize OCF request allocation utility
 *
 * @param cache - OCF cache instance
 * @return Operation status 0 - successful, non-zero failure
 */
int ocf_rq_allocator_init(struct ocf_ctx *ocf_ctx);

/**
 * @brief De-initialize OCF request allocation utility
 *
 * @param cache - OCF cache instance
 */
void ocf_rq_allocator_deinit(struct ocf_ctx *ocf_ctx);

/**
 * @brief Allocate new OCF request
 *
 * @param cache - OCF cache instance
 * @param core_id - Core id
 * @param addr - LBA of request
 * @param bytes - number of bytes of request
 * @param rw - Read or Write
 *
 * @return new OCF request
 */
struct ocf_request *ocf_rq_new(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t addr, uint32_t bytes, int rw);

/**
 * @brief Allocate OCF request map
 *
 * @param rq OCF request
 *
 * @retval 0 Allocation succeed
 * @retval non-zero Allocation failed
 */
int ocf_rq_alloc_map(struct ocf_request *rq);

/**
 * @brief Allocate new OCF request with NOIO map allocation for huge request
 *
 * @param cache - OCF cache instance
 * @param core_id - Core id
 * @param addr - LBA of request
 * @param bytes - number of bytes of request
 * @param rw - Read or Write
 *
 * @return new OCF request
 */

struct ocf_request *ocf_rq_new_extended(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t addr, uint32_t bytes, int rw);

/**
 * @brief Allocate new OCF request for DISCARD operation
 *
 * @param cache - OCF cache instance
 * @param core_id - Core id
 * @param addr - LBA of request
 * @param bytes - number of bytes of request
 * @param rw - Read or Write
 *
 * @return new OCF request
 */
struct ocf_request *ocf_rq_new_discard(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t addr, uint32_t bytes, int rw);

/**
 * @brief Get number of allocated requests
 *
 * @param cache OCF cache instance
 *
 * @return Number of allocated requests
 */
uint32_t ocf_rq_get_allocated(struct ocf_cache *cache);

/**
 * @brief Increment OCF request reference count
 *
 * @param rq - OCF request
 */
void ocf_rq_get(struct ocf_request *rq);

/**
 * @brief Decrement OCF request reference. If reference is 0 then request will
 * be deallocated
 *
 * @param rq - OCF request
 */
void ocf_rq_put(struct ocf_request *rq);

/**
 * @brief Clear OCF request info
 *
 * @param rq - OCF request
 */
void ocf_rq_clear_info(struct ocf_request *rq);

/**
 * @brief Clear OCF request map
 *
 * @param rq - OCF request
 */
void ocf_rq_clear_map(struct ocf_request *rq);

/**
 * @brief Clear OCF request
 *
 * @param rq - OCF request
 */
static inline void ocf_rq_clear(struct ocf_request *rq)
{
	ocf_rq_clear_info(rq);
	ocf_rq_clear_map(rq);

	env_atomic_set(&rq->lock_remaining, 0);
	env_atomic_set(&rq->req_remaining, 0);
}

/**
 * @brief Return OCF request reference count
 *
 * @param rq - OCF request
 * @return OCF request reference count
 */
static inline int ocf_rq_ref_count(struct ocf_request *rq)
{
	return env_atomic_read(&rq->ref_count);
}

static inline bool ocf_rq_is_4k(uint64_t addr, uint32_t bytes)
{
	return !((addr % PAGE_SIZE) || (bytes % PAGE_SIZE));
}

#endif /* UTILS_RQ_H_ */
