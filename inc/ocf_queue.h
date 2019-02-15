/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef OCF_QUEUE_H_
#define OCF_QUEUE_H_

/**
 * @file
 * @brief OCF queues API
 */

/**
 * @brief Allocate IO queue and add it to list in cache
 *
 * @param[in] cache Handle to cache instance
 * @param[in] id Id assigned to newely created queue
 *
 */
ocf_queue_t ocf_queue_alloc(ocf_cache_t cache, uint32_t id);

/**
 * @brief Run thread for given IO queue
 *
 * @param[in] queue Handle queue
 *
 */
int ocf_queue_start(ocf_queue_t queue);

/**
 * @brief Stop thread for given IO queue
 *
 * @param[in] queue Handle queue
 *
 */
void ocf_queue_stop(ocf_queue_t queue);

/**
 * @brief Remove queue from cache instance
 *
 * @param[in] queue Handle queue
 *
 */
void ocf_queue_free(ocf_queue_t queue);

/**
 * @brief Process single request from queue
 *
 * @param[in] q Queue to run
 */
void ocf_queue_run_single(ocf_queue_t q);

/**
 * @brief Run queue processing
 *
 * @param[in] q Queue to run
 */
void ocf_queue_run(ocf_queue_t q);

/**
 * @brief Set queue private data
 *
 * @param[in] q I/O queue
 * @param[in] priv Private data
 */
void ocf_queue_set_priv(ocf_queue_t q, void *priv);

/**
 * @brief Get queue private data
 *
 * @param[in] q I/O queue
 *
 * @retval I/O queue private data
 */
void *ocf_queue_get_priv(ocf_queue_t q);

/**
 * @brief Get number of pending requests in I/O queue
 *
 * @param[in] q I/O queue
 *
 * @retval Number of pending requests in I/O queue
 */
uint32_t ocf_queue_pending_io(ocf_queue_t q);

/**
 * @brief Get I/O queue id
 *
 * @param[in] q I/O queue
 *
 * @retval Id I/O queue
 */
uint32_t ocf_queue_get_id(ocf_queue_t q);

/**
 * @brief Get cache instance to which I/O queue belongs
 *
 * @param[in] q I/O queue
 *
 * @retval Cache instance
 */
ocf_cache_t ocf_queue_get_cache(ocf_queue_t q);

#endif
