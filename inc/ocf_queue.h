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
 * @brief Get cache instance to which I/O queue belongs
 *
 * @param[in] q I/O queue
 *
 * @retval Cache instance
 */
ocf_cache_t ocf_queue_get_cache(ocf_queue_t q);

/**
 * @brief Get I/O queue id
 *
 * @param[in] q I/O queue
 *
 * @retval I/O queue id
 */
uint32_t ocf_queue_get_id(ocf_queue_t q);

#endif
