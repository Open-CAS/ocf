/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef OCF_CLEANER_H_
#define OCF_CLEANER_H_

/**
 * @file
 * @brief OCF cleaner API for synchronization dirty data
 *
 */

/**
 * @brief Run cleaner
 *
 * @param[in] c Cleaner instance to run
 * @param[in] io_queue I/O queue to which cleaner requests should be submitted
 *
 * @retval Hint when to run cleaner next time. Value expressed in miliseconds.
 */
uint32_t ocf_cleaner_run(ocf_cleaner_t c, uint32_t io_queue);

/**
 * @brief Set cleaner private data
 *
 * @param[in] c Cleaner handle
 * @param[in] priv Private data
 */
void ocf_cleaner_set_priv(ocf_cleaner_t c, void *priv);

/**
 * @brief Get cleaner private data
 *
 * @param[in] c Cleaner handle
 *
 * @retval Cleaner private data
 */
void *ocf_cleaner_get_priv(ocf_cleaner_t c);

/**
 * @brief Get cache instance to which cleaner belongs
 *
 * @param[in] c Cleaner handle
 *
 * @retval Cache instance
 */
ocf_cache_t ocf_cleaner_get_cache(ocf_cleaner_t c);

#endif
