/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "../metadata/metadata.h"

#include "nhit.h"

ocf_error_t nhit_init(ocf_cache_t cache, ocf_promotion_policy_t policy)
{
	return 0;
}

void nhit_deinit(ocf_promotion_policy_t policy)
{

}

ocf_error_t nhit_set_param(ocf_promotion_policy_t policy, uint8_t param_id,
		uint64_t param_value)
{
	return 0;
}

void nhit_req_purge(ocf_promotion_policy_t policy,
		struct ocf_request *req)
{

}

bool nhit_req_should_promote(ocf_promotion_policy_t policy, struct ocf_request *req)
{
	return true;
}

