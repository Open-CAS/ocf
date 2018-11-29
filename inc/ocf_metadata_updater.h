/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_METADATA_UPDATER_H__
#define __OCF_METADATA_UPDATER_H__

/**
 * @file
 * @brief OCF metadata updater API
 *
 */

/**
 * @brief Run metadata updater
 *
 * @param[in] mu Metadata updater instance to run
 *
 * @retval Hint if there is need to rerun without waiting.
 */
uint32_t ocf_metadata_updater_run(ocf_metadata_updater_t mu);

/**
 * @brief Set metadata updater private data
 *
 * @param[in] c Metadata updater handle
 * @param[in] priv Private data
 */
void ocf_metadata_updater_set_priv(ocf_metadata_updater_t mu, void *priv);

/**
 * @brief Get metadata updater private data
 *
 * @param[in] c Metadata updater handle
 *
 * @retval Metadata updater private data
 */
void *ocf_metadata_updater_get_priv(ocf_metadata_updater_t mu);

/**
 * @brief Get cache instance to which metadata updater belongs
 *
 * @param[in] c Metadata updater handle
 *
 * @retval Cache instance
 */
ocf_cache_t ocf_metadata_updater_get_cache(ocf_metadata_updater_t mu);

#endif /* __OCF_METADATA_UPDATER_H__ */
