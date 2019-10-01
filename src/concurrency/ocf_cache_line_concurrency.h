/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef OCF_CACHE_CONCURRENCY_H_
#define OCF_CACHE_CONCURRENCY_H_

/**
 * @file utils_req.h
 * @brief OCF cache concurrency module
 */

/**
 * @brief OCF cache concurrency module handle
 */
struct ocf_cache_line_concurrency;

/**
 * @brief Initialize OCF cache concurrency module
 *
 * @param cache - OCF cache instance
 * @return 0 - Initialization successful, otherwise ERROR
 */
int ocf_cache_line_concurrency_init(struct ocf_cache *cache);

/**
 * @biref De-Initialize  OCF cache concurrency module
 *
 * @param cache - OCF cache instance
 */
void ocf_cache_line_concurrency_deinit(struct ocf_cache *cache);

/**
 * @brief Get number of waiting (suspended) OCF requests in due to cache
 * overlapping
 *
 * @param cache - OCF cache instance
 *
 * @return Number of suspended OCF requests
 */
uint32_t ocf_cache_line_concurrency_suspended_no(struct ocf_cache *cache);

/**
 * @brief Return memory footprint conusmed by cache concurrency module
 *
 * @param cache - OCF cache instance
 *
 * @return Memory footprint of cache concurrency module
 */
size_t ocf_cache_line_concurrency_size_of(struct ocf_cache *cache);

/* async request cacheline lock acquisition callback */
typedef void (*ocf_req_async_lock_cb)(struct ocf_request *req);

/**
 * @brief Lock OCF request for write access (Lock all cache lines in map info)
 *
 * @param req - OCF request
 * @param cb - async lock acquisition callback
 *
 * @returns lock acquisition status or negative error code in case of internal
 *		error
 * @retval OCF_LOCK_ACQUIRED - OCF request has been locked and can be processed
 * @retval OCF_LOCK_NOT_ACQUIRED - OCF request lock not acquired, request was
 * added into waiting list. When lock will be acquired @cb cllback be called
 */
int ocf_req_async_lock_wr(struct ocf_request *req, ocf_req_async_lock_cb cb);

/**
 * @brief Lock OCF request for read access (Lock all cache lines in map info)
 *
 * @param req - OCF request
 * @param cb - async lock acquisition callback
 *
 * @returns lock acquisition status or negative error code in case of internal
 *		error
 * @retval OCF_LOCK_ACQUIRED - OCF request has been locked and can be processed
 * @retval OCF_LOCK_NOT_ACQUIRED - OCF request lock not acquired, request was
 * added into waiting list. When lock will be acquired @cb callback be called
 */
int ocf_req_async_lock_rd(struct ocf_request *req, ocf_req_async_lock_cb cb);

/**
 * @brief Unlock OCF request from write access
 *
 * @param req - OCF request
 */
void ocf_req_unlock_wr(struct ocf_request *req);

/**
 * @brief Unlock OCF request from read access
 *
 * @param req - OCF request
 */
void ocf_req_unlock_rd(struct ocf_request *req);

/**
 * @brief Unlock OCF request from read or write access
 *
 * @param req - OCF request
 */
void ocf_req_unlock(struct ocf_request *req);

/**
 * @Check if cache line is used.
 *
 * Cache line is used when:
 * 1. It is locked for write or read access
 * or
 * 2. There is set locked bit in metadata
 *
 * @param cache - OCF cache instance
 * @param line - Cache line to be unlocked
 *
 * @retval true - cache line is used
 * @retval false - cache line is not used
 */
bool ocf_cache_line_is_used(struct ocf_cache *cache,
		ocf_cache_line_t line);

/**
 * @brief Check if for specified cache line there are waiters
 * on the waiting list
 *
 * @param cache - OCF cache instance
 * @param line - Cache line to be checked for waiters
 *
 * @retval true - there are waiters
 * @retval false - No waiters
 */
bool ocf_cache_line_are_waiters(struct ocf_cache *cache,
		ocf_cache_line_t line);

/**
 * @brief un_lock request map info entry from from write or read access.
 *
 * @param cache - OCF cache instance
 * @param req - OCF request
 * @param entry - request map entry number
 */
void ocf_req_unlock_entry(struct ocf_cache *cache,
		struct ocf_request *req, uint32_t entry);

/**
 * @brief Release cache line read lock
 *
 * @param cache - OCF cache instance
 * @param line - Cache line to be unlocked
 */
void ocf_cache_line_unlock_rd(struct ocf_cache *cache, ocf_cache_line_t line);

/**
 * @brief Attempt to lock cache line for read
 *
 * @param cache - OCF cache instance
 * @param line - Cache line to be checked for waiters
 *
 * @retval true - read lock successfully acquired
 * @retval false - failed to acquire read lock
 */
bool ocf_cache_line_try_lock_rd(struct ocf_cache *cache, ocf_cache_line_t line);

#endif /* OCF_CONCURRENCY_H_ */
