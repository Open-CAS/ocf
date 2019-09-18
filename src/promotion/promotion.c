/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "../metadata/metadata.h"

#include "promotion.h"
#include "ops.h"
#include "nhit/nhit.h"

struct promotion_policy_ops ocf_promotion_policies[ocf_promotion_max] = {
	[ocf_promotion_always] = {
		.name = "always",
	},
	[ocf_promotion_nhit] = {
		.name = "nhit",
		.init = nhit_init,
		.deinit = nhit_deinit,
		.set_param = nhit_set_param,
		.get_param = nhit_get_param,
		.req_purge = nhit_req_purge,
		.req_should_promote = nhit_req_should_promote,
	},
};

ocf_error_t ocf_promotion_init(ocf_cache_t cache, ocf_promotion_policy_t *policy)
{
	ocf_promotion_t type = cache->conf_meta->promotion_policy_type;
	ocf_error_t result = 0;

	ENV_BUG_ON(type >= ocf_promotion_max);

	*policy = env_vmalloc(sizeof(**policy));
	if (!*policy)
		return -OCF_ERR_NO_MEM;

	(*policy)->type = type;
	(*policy)->owner = cache;

	if (ocf_promotion_policies[type].init)
		result = ocf_promotion_policies[type].init(cache, *policy);

	return result;
}

void ocf_promotion_deinit(ocf_promotion_policy_t policy)
{
	ocf_promotion_t type = policy->type;

	ENV_BUG_ON(type >= ocf_promotion_max);

	if (ocf_promotion_policies[type].deinit)
		ocf_promotion_policies[type].deinit(policy);

	env_vfree(policy);
}

ocf_error_t ocf_promotion_set_policy(ocf_promotion_policy_t policy,
		ocf_promotion_t type)
{
	ocf_error_t result = 0;
	ocf_cache_t cache = policy->owner;
	ocf_promotion_t prev_policy;

	if (type >= ocf_promotion_max)
		return -OCF_ERR_INVAL;

	prev_policy = cache->conf_meta->promotion_policy_type;

	if (ocf_promotion_policies[prev_policy].deinit)
		ocf_promotion_policies[prev_policy].deinit(policy);

	cache->conf_meta->promotion_policy_type = type;
	policy->type = type;

	if (ocf_promotion_policies[type].init)
		result = ocf_promotion_policies[type].init(cache, policy);

	if (result) {
		ocf_cache_log(cache, log_err,
				"Error switching to new promotion policy\n");
		ocf_cache_log(cache, log_err,
				"Falling back to 'always' promotion policy\n");
		cache->conf_meta->promotion_policy_type = ocf_promotion_always;
		policy->type = ocf_promotion_always;
	}

	return result;
}

ocf_error_t ocf_promotion_set_param(ocf_promotion_policy_t policy,
		uint8_t param_id, uint64_t param_value)
{
	ocf_promotion_t type = policy->type;
	ocf_error_t result = -OCF_ERR_INVAL;

	ENV_BUG_ON(type >= ocf_promotion_max);

	if (ocf_promotion_policies[type].set_param) {
		result = ocf_promotion_policies[type].set_param(policy, param_id,
				param_value);
	}

	return result;
}

ocf_error_t ocf_promotion_get_param(ocf_promotion_policy_t policy,
		uint8_t param_id, uint64_t *param_value)
{
	ocf_promotion_t type = policy->type;
	ocf_error_t result = -OCF_ERR_INVAL;

	ENV_BUG_ON(type >= ocf_promotion_max);

	if (ocf_promotion_policies[type].get_param) {
		result = ocf_promotion_policies[type].get_param(policy, param_id,
				param_value);
	}

	return result;
}

void ocf_promotion_req_purge(ocf_promotion_policy_t policy,
		struct ocf_request *req)
{
	ocf_promotion_t type = policy->type;

	ENV_BUG_ON(type >= ocf_promotion_max);

	if (ocf_promotion_policies[type].req_purge)
		ocf_promotion_policies[type].req_purge(policy, req);
}

bool ocf_promotion_req_should_promote(ocf_promotion_policy_t policy,
		struct ocf_request *req)
{
	ocf_promotion_t type = policy->type;
	bool result = true;

	ENV_BUG_ON(type >= ocf_promotion_max);

	if (ocf_promotion_policies[type].req_should_promote) {
		result = ocf_promotion_policies[type].req_should_promote(policy,
				req);
	}

	return result;
}

