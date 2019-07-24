/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef OCF_CONCURRENCY_H_
#define OCF_CONCURRENCY_H_

#include "../ocf_cache_priv.h"

/**
 * @file utils_req.h
 * @brief OCF concurrency
 */

/**
 * @brief Lock result - Lock acquired successfully
 */
#define OCF_LOCK_ACQUIRED		0

/**
 * @brief Lock result - Lock not acquired, lock request added into waiting list
 */
#define OCF_LOCK_NOT_ACQUIRED		1

/**
 * @brief Initialize OCF concurrency module
 *
 * @param cache - OCF cache instance
 * @return 0 - Initialization successful, otherwise ERROR
 */
int ocf_concurrency_init(struct ocf_cache *cache);

/**
 * @biref De-Initialize  OCF concurrency module
 *
 * @param cache - OCF cache instance
 */
void ocf_concurrency_deinit(struct ocf_cache *cache);

#include "ocf_cache_line_concurrency.h"

#endif /* OCF_CONCURRENCY_H_ */
