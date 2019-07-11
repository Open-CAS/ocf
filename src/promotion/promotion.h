/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef PROMOTION_H_
#define PROMOTION_H_

#include "ocf/ocf.h"
#include "../ocf_request.h"

typedef struct ocf_promotion_policy *ocf_promotion_policy_t;
/**
 * @brief Allocate and initialize promotion policy. Should be called after cache
 * metadata has been allocated and cache->conf_meta->promotion_policy_type has
 * been set.
 *
 * @param[in] cache OCF cache instance
 * @param[out] param initialized policy handle
 *
 * @retval ocf_error_t
 */
ocf_error_t ocf_promotion_init(ocf_cache_t cache, ocf_promotion_policy_t *policy);

/**
 * @brief Stop, deinitialize and free promotion policy structures.
 *
 * @param[in] policy promotion policy handle
 *
 * @retval none
 */
void ocf_promotion_deinit(ocf_promotion_policy_t policy);

/**
 * @brief Set promotion policy parameter
 *
 * @param[in] policy promotion policy handle
 * @param[in] param_id id of parameter to be set
 * @param[in] param_value value of parameter to be set
 *
 * @retval ocf_error_t
 */
ocf_error_t ocf_promotion_set_param(ocf_promotion_policy_t policy,
		uint8_t param_id, uint64_t param_value);

/**
 * @brief Update promotion policy after cache lines have been promoted to cache
 * or discarded from core device
 *
 * @param[in] policy promotion policy handle
 * @param[in] req OCF request to be purged
 *
 * @retval none
 */
void ocf_promotion_req_purge(ocf_promotion_policy_t policy,
		struct ocf_request *req);

/**
 * @brief Check in promotion policy whether core lines in request can be promoted
 *
 * @param[in] policy promotion policy handle
 * @param[in] req OCF request which is to be promoted
 *
 * @retval should core lines belonging to this request be promoted
 */
bool ocf_promotion_req_should_promote(ocf_promotion_policy_t policy,
		struct ocf_request *req);

#endif /* PROMOTION_H_ */
