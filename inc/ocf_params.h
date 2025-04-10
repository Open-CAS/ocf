/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PARAMS_H__
#define __OCF_PARAMS_H__

#include "ocf_env.h"

#define OCF_MAX_PARAM_NAME_LEN	(32)
#define OCF_MAX_POLICY_NAME	(OCF_MAX_PARAM_NAME_LEN)
#define OCF_MAX_PARAMS_POLICIES	(8)
#define OCF_MAX_ENABLE_STR	(8)
#define OCF_PREFETCHER_ENABLE_ALL 	(0xFE)
#define OCF_PREFETCHER_DISABLE_ALL 	(0)
#define OCF_CLASSIFIER_ENABLE_ALL 	(0xFF)
#define OCF_CLASSIFIER_DISABLE_ALL 	(1<<0)

struct ocf_policy_info {
	char policy_name[OCF_MAX_POLICY_NAME];
	bool enable;
};

struct ocf_policy_list {
	int list_size;
	struct ocf_policy_info policy_info[OCF_MAX_PARAMS_POLICIES];
};

/**
 * @brief Set cache parameter in given cache
 *
 * @attention This changes only runtime state. To make changes persistent
 *            use function ocf_mngt_cache_save().
 *
 * @param[in] cache Cache handle
 * @param[in] param_name Parameter name
 * @param[in] policy_list list of policies to enable/disable
 *
 * @retval 0 Cache parameter have been set successfully
 * @retval Non-zero Error occurred and cache parameter not been set
 */
int ocf_cache_set_ocf_param(ocf_cache_t cache, const char *param_name,
	bool enable, struct ocf_policy_list *policy_list);

/**
 * @brief Get cache parameter in given cache
 *
 * @param[in] cache Cache handle
 * @param[in] param_name Parameter name
 * @param[out] policy_list list of policies and their enable/disable state
 *
 * @retval 0 Cache parameter have been found successfully
 * @retval Non-zero Error occurred and cache parameter not been found
 */
int ocf_cache_get_ocf_param_value(ocf_cache_t cache,
	const char *param_name, struct ocf_policy_list *policy_list);

/**
 * @brief Set core parameter in given core
 *
 * @attention This changes only runtime state.
 *
 * @param[in] core Core handle
 * @param[in] param_name Parameter name
 * @param[in] policy_list list of policies to enable/disable
 *
 * @retval 0 core parameter have been set successfully
 * @retval Non-zero Error occurred and core parameter not been set
 */
int ocf_core_set_ocf_param(ocf_core_t core, const char *param_name,
	bool enable, struct ocf_policy_list *policy_list);

/**
 * @brief Get core parameter in core cache
 *
 * @param[in] core Core handle
 * @param[in] param_name Parameter name
 * @param[out] policy_list list of policies and their enable/disable state
 *
 * @retval 0 Core parameter have been found successfully
 * @retval Non-zero Error occurred and core parameter not been found
 */
int ocf_core_get_ocf_param_value(ocf_core_t core,
	const char *param_name, struct ocf_policy_list *policy_list);

/**
 * @brief Parse comma separated policy string to policy list struct
 *
 * @param[in] policy policy list string (comma separated)
 * @param[out] policy_list list of policies struct
 *
 */
void ocf_parse_policy_list(const char *policy, struct ocf_policy_list *policy_list);


#endif	// __OCF_PARAMS_H__
