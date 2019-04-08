/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef UTILS_RQ_H_
#define UTILS_RQ_H_

#include "../ocf_request.h"

/**
 * @file utils_req.h
 * @brief OCF request allocation utilities
 */

struct ocf_req_allocator;

/**
 * @brief Initialize OCF request allocation utility
 *
 * @param cache - OCF cache instance
 * @return Operation status 0 - successful, non-zero failure
 */
int ocf_req_allocator_init(struct ocf_ctx *ocf_ctx);

/**
 * @brief De-initialize OCF request allocation utility
 *
 * @param cache - OCF cache instance
 */
void ocf_req_allocator_deinit(struct ocf_ctx *ocf_ctx);

/**
 * @brief Allocate new OCF request
 *
 * @param out_req - new OCF request
 * @param queue - I/O queue handle
 * @param core - OCF core instance
 * @param addr - LBA of request
 * @param bytes - number of bytes of request
 * @param rw - Read or Write
 *
 * @retval 0 Allocation succeeded
 * @retval -EBUSY Unable to create request due to in-progress mngmt operation
 * @retval -ENOMEM Memory allocation failure
 */
int ocf_req_new(struct ocf_request **out_req, ocf_queue_t queue,
		ocf_core_t core, uint64_t addr, uint32_t bytes, int rw);

/**
 * @brief Allocate OCF request map
 *
 * @param req OCF request
 *
 * @retval 0 Allocation succeed
 * @retval non-zero Allocation failed
 */
int ocf_req_alloc_map(struct ocf_request *req);

/**
 * @brief Allocate new OCF request with NOIO map allocation for huge request
 *
 * @param out_req - new OCF request
 * @param queue - I/O queue handle
 * @param core - OCF core instance
 * @param addr - LBA of request
 * @param bytes - number of bytes of request
 * @param rw - Read or Write
 *
 * @retval 0 Allocation succeeded
 * @retval -EBUSY Unable to create request due to in-progress mngmt operation
 * @retval -ENOMEM Memory allocation failure
 */

int ocf_req_new_extended(struct ocf_request **out_req, ocf_queue_t queue,
		ocf_core_t core, uint64_t addr, uint32_t bytes, int rw);

/**
 * @brief Allocate new OCF request for DISCARD operation
 *
 * @param out_req - new OCF request
 * @param queue - I/O queue handle
 * @param core - OCF core instance
 * @param addr - LBA of request
 * @param bytes - number of bytes of request
 * @param rw - Read or Write
 *
 * @retval 0 Allocation succeeded
 * @retval -EBUSY Unable to create request due to in-progress mngmt operation
 * @retval -ENOMEM Memory allocation failure
 */
int ocf_req_new_discard(struct ocf_request **out_req, ocf_queue_t queue,
		ocf_core_t core, uint64_t addr, uint32_t bytes, int rw);

/**
 * @brief Get number of allocated requests
 *
 * @param cache OCF cache instance
 *
 * @return Number of allocated requests
 */
uint32_t ocf_req_get_allocated(struct ocf_cache *cache);

/**
 * @brief Increment OCF request reference count
 *
 * @param req - OCF request
 */
void ocf_req_get(struct ocf_request *req);

/**
 * @brief Decrement OCF request reference. If reference is 0 then request will
 * be deallocated
 *
 * @param req - OCF request
 */
void ocf_req_put(struct ocf_request *req);

/**
 * @brief Clear OCF request info
 *
 * @param req - OCF request
 */
void ocf_req_clear_info(struct ocf_request *req);

/**
 * @brief Clear OCF request map
 *
 * @param req - OCF request
 */
void ocf_req_clear_map(struct ocf_request *req);

/**
 * @brief Clear OCF request
 *
 * @param req - OCF request
 */
static inline void ocf_req_clear(struct ocf_request *req)
{
	ocf_req_clear_info(req);
	ocf_req_clear_map(req);

	env_atomic_set(&req->lock_remaining, 0);
	env_atomic_set(&req->req_remaining, 0);
}

/**
 * @brief Return OCF request reference count
 *
 * @param req - OCF request
 * @return OCF request reference count
 */
static inline int ocf_req_ref_count(struct ocf_request *req)
{
	return env_atomic_read(&req->ref_count);
}

static inline bool ocf_req_is_4k(uint64_t addr, uint32_t bytes)
{
	return !((addr % PAGE_SIZE) || (bytes % PAGE_SIZE));
}

#endif /* UTILS_RQ_H_ */
