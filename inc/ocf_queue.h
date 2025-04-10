/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef OCF_QUEUE_H_
#define OCF_QUEUE_H_

/**
 * @file
 * @brief OCF queues API
 */

/**
 * @brief I/O queue operations
 */
struct ocf_queue_ops {
	/**
	 * @brief Kick I/O queue processing
	 *
	 * This function should inform worker, thread or any other queue
	 * processing mechanism, that there are new requests in queue to
	 * be processed. Processing requests synchronously in this function
	 * is not allowed.
	 *
	 * @param[in] q I/O queue to be kicked
	 */
	void (*kick)(ocf_queue_t q);

	/**
	 * @brief Kick I/O queue processing
	 *
	 * This function should inform worker, thread or any other queue
	 * processing mechanism, that there are new requests in queue to
	 * be processed. Function kick_sync is allowed to process requests
	 * synchronously without delegating them to the worker.
	 *
	 * @param[in] q I/O queue to be kicked
	 */
	void (*kick_sync)(ocf_queue_t q);

	/**
	 * @brief Stop I/O queue
	 *
	 * @param[in] q I/O queue beeing stopped
	 */
	void (*stop)(ocf_queue_t q);
};

/**
 * @brief Allocate IO queue and add it to list in cache
 *
 * @param[in] cache Handle to cache instance
 * @param[out] queue Handle to created queue
 * @param[in] ops Queue operations
 *
 * @return Zero on success, otherwise error code
 */
int ocf_queue_create(ocf_cache_t cache, ocf_queue_t *queue,
		const struct ocf_queue_ops *ops);

/**
 * @brief Allocate mngt queue and assign it to cache
 *
 * @param[in] cache Handle to cache instance
 * @param[out] queue Handle to created queue
 * @param[in] ops Queue operations
 *
 * @return Zero on success, otherwise error code
 */
int ocf_queue_create_mngt(ocf_cache_t cache, ocf_queue_t *queue,
		const struct ocf_queue_ops *ops);

/**
 * @brief Queue visitor function
 * @param[in] queue Queue handle
 * @param[in] ctx Visitor function context
 *
 * @return Zero on success, otherwise error code
 */
typedef int (*ocf_cache_queue_visitor_t)(ocf_queue_t queue, void *ctx);

/**
 * @brief Call @visitor for every IO queue
 *
 * @param[in] cache Cache instance
 * @param[in] visitor Function to be called on every queue.
 *		The visitor function is called in atomic context
 * @param[in] ctx Context to be passes to @visitor
 *
 * @return Zero on success, otherwise error code
 */
int ocf_queue_visit(ocf_cache_t cache, ocf_cache_queue_visitor_t visitor,
		void *ctx);

/**
 * @brief Increase reference counter in queue
 *
 * @param[in] queue Queue
 *
 */
void ocf_queue_get(ocf_queue_t queue);

/**
 * @brief Decrease reference counter in queue
 *
 * @note If queue don't have any reference - deallocate it
 *
 * @param[in] queue Queue
 *
 */
void ocf_queue_put(ocf_queue_t queue);

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
 * @brief Return if queue is management queue
 *
 * @param[in] queue - queue object
 *
 * @retval true - if management queue, otherwise false
 */
bool ocf_queue_is_mngt(ocf_queue_t queue);

#endif
