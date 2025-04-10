/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Implementation for set and get ocf parameters
 */

#include "ocf/ocf_types.h"
#include "../ocf_cache_priv.h"
#include "../ocf_core_priv.h"
#include "ocf/ocf_params.h"

static void cache_flush_end(ocf_cache_t cache,
	void *priv, int error)
{
	if (error) {
		ocf_cache_log(cache, log_err, "cache flush failed with error:%d\n", error);
	} else {
		ocf_cache_log(cache, log_info, "Cache flush ended successfully\n");
	}
}

static void core_flush_end(ocf_core_t core,
	void *priv, int error)
{
	if (error) {
		ocf_core_log(core, log_err, "Core flush failed with error:%d\n", error);
	} else {
		ocf_core_log(core, log_info, "Core flush ended successfully\n");
	}
}

static void set_per_core_ocf_prefetcher(ocf_cache_t cache)
{
	if (cache) {
		ocf_core_t core;
		ocf_core_id_t core_id;

		for_each_core(cache, core, core_id) {
			core->ocf_prefetcher = cache->ocf_prefetcher;
		}
	}
}

void ocf_parse_policy_list(const char *policy, struct ocf_policy_list *policy_list)
{
	if (!policy) {
		policy_list->list_size = 0;
	} else {
		char *policy_val;
		char policy_str[OCF_MAX_POLICY_NAME * OCF_MAX_PARAMS_POLICIES];
		char *rest = policy_str;
		int i = 0;

		env_strncpy(rest, sizeof(policy_str), policy, (OCF_MAX_POLICY_NAME * OCF_MAX_PARAMS_POLICIES) - 1);
		while ((policy_val = strsep(&rest, ","))) {
			env_strncpy(policy_list->policy_info[i++].policy_name, OCF_MAX_POLICY_NAME,
				policy_val, OCF_MAX_POLICY_NAME);
			if (i == OCF_MAX_PARAMS_POLICIES) {
				break;
			}
		}
		policy_list->list_size = i;
	}
}

static int ocf_set_ocf_param(ocf_cache_t cache_to_for_all, ocf_core_t core, uint8_t *ocf_classifier, uint8_t *ocf_prefetcher,
	const char *param_name, bool enable, struct ocf_policy_list *policy_list, bool *flush_needed)
{
	int result = 0;
	int i;
	*flush_needed = false;

	if (!env_strncmp(param_name, OCF_MAX_PARAM_NAME_LEN,
		"ocf_prefetcher", OCF_MAX_PARAM_NAME_LEN)) {
		if (policy_list->list_size == 0) {
			*ocf_prefetcher = enable? OCF_PREFETCHER_ENABLE_ALL: OCF_PREFETCHER_DISABLE_ALL;
			set_per_core_ocf_prefetcher(cache_to_for_all);
			return result;
		}
		for (i = 0; i < policy_list->list_size; i++) {
			if (!env_strncmp(policy_list->policy_info[i].policy_name, OCF_MAX_POLICY_NAME,
				"stream", OCF_MAX_POLICY_NAME)) {
				*ocf_prefetcher = enable ? (*ocf_prefetcher | pa_mask_stream) :
					(*ocf_prefetcher & ~pa_mask_stream);
				set_per_core_ocf_prefetcher(cache_to_for_all);
			} else {
				result = -OCF_ERR_INVAL;
			}
		}
	} else {
		result = -OCF_ERR_INVAL;
	}

	return result;
}

static void create_policy_str(const struct ocf_policy_list *policy_list,
	char *str, uint32_t strl)
{
	const char *s;
	uint32_t i;
	int n;

	str[0] = '\0';
	n = 0;
	for (i = 0; i < policy_list->list_size; i++) {
		s = policy_list->policy_info[i].policy_name;
		if (*s == '\0')
			continue; /* skip empty strings */
		n += snprintf(str + n, strl - n, "%s,", s);
		if (n > strl) { /* string overflow, return empty string */
			str[0] = '\0';
			return;
		}
	}
	/* remove the last comma */
	if (n) {
		n--;
		str[n] = '\0';
	}
}

int ocf_cache_set_ocf_param(ocf_cache_t cache, const char *param_name,
	bool enable, struct ocf_policy_list *policy_list)
{
	int result;
	bool flush_needed;
	OCF_CHECK_NULL(cache);

	result = ocf_set_ocf_param(cache, NULL, &cache->ocf_classifier, &cache->ocf_prefetcher,
		param_name, enable, policy_list, &flush_needed);

	if (flush_needed) {
		ocf_mngt_cache_flush(cache, cache_flush_end, NULL);
	}

	if (result) {
		char policy_str[OCF_MAX_POLICY_NAME * OCF_MAX_PARAMS_POLICIES];
		create_policy_str(policy_list, policy_str, sizeof(policy_str));
		ocf_cache_log(cache, log_err, "Setting cache ocf param '%s' with value '%s' "
				"for policies '%s' failed\n", param_name, enable? "on": "off", policy_str);
	}

	return result;
}

int ocf_core_set_ocf_param(ocf_core_t core, const char *param_name,
	bool enable, struct ocf_policy_list *policy_list)
{
	int result;
	bool flush_needed;
	ocf_cache_t cache;
	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);

	if (!ocf_cache_is_standby(cache))
		result = -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		result = -OCF_ERR_CACHE_DETACHED;

	result = ocf_set_ocf_param(NULL, core, &core->ocf_classifier, &core->ocf_prefetcher,
		param_name, enable, policy_list, &flush_needed);

	if (flush_needed) {
		ocf_mngt_core_flush(core, core_flush_end, NULL);
	}

	if (result) {
		char policy_str[OCF_MAX_POLICY_NAME * OCF_MAX_PARAMS_POLICIES];
		create_policy_str(policy_list, policy_str, sizeof(policy_str));
		ocf_core_log(core, log_err, "Setting core ocf param '%s' with value '%s' "
				"for policies '%s' failed\n", param_name, enable? "on": "off", policy_str);
	}

	return result;
}

static int ocf_get_ocf_param_value(uint8_t *ocf_classifier, uint8_t *ocf_prefetcher,
	const char *param_name, struct ocf_policy_list *policy_list)
{
	int result = 0;
	int i;

	if (!env_strncmp(param_name, OCF_MAX_PARAM_NAME_LEN, "ocf_prefetcher", OCF_MAX_PARAM_NAME_LEN)) {
		if (policy_list->list_size == 0) {
			policy_list->list_size = 1;
			env_strncpy(policy_list->policy_info[0].policy_name, OCF_MAX_POLICY_NAME,
				"stream", OCF_MAX_POLICY_NAME);
		}
		for (i = 0; i < policy_list->list_size; i++) {
			if (!env_strncmp(policy_list->policy_info[i].policy_name, OCF_MAX_POLICY_NAME,
				"stream", OCF_MAX_POLICY_NAME)) {
				policy_list->policy_info[i].enable = !!(*ocf_prefetcher & pa_mask_stream);
			} else {
				result = -OCF_ERR_INVAL;
			}
		}
	} else {
		result = -OCF_ERR_INVAL;
	}
	return result;
}

int ocf_cache_get_ocf_param_value(ocf_cache_t cache,
	const char *param_name, struct ocf_policy_list *policy_list)
{
	int result;
	OCF_CHECK_NULL(cache);

	result = ocf_get_ocf_param_value(&cache->ocf_classifier, &cache->ocf_prefetcher, param_name,
		policy_list);

	if (result) {
		char policy_str[OCF_MAX_POLICY_NAME*OCF_MAX_PARAMS_POLICIES];
		create_policy_str(policy_list, policy_str, sizeof(policy_str));
		ocf_cache_log(cache, log_err, "Get cache ocf param '%s' "
				"for policies '%s' failed\n", param_name, policy_str);
	}

	return result;
}

int ocf_core_get_ocf_param_value(ocf_core_t core,
	const char *param_name, struct ocf_policy_list *policy_list)
{
	int result;
	OCF_CHECK_NULL(core);

	result = ocf_get_ocf_param_value(&core->ocf_classifier, &core->ocf_prefetcher, param_name,
		policy_list);

	if (result) {
		char policy_str[OCF_MAX_POLICY_NAME * OCF_MAX_PARAMS_POLICIES];
		create_policy_str(policy_list, policy_str, sizeof(policy_str));
		ocf_core_log(core, log_err, "Get cache ocf param '%s' "
				"for policies '%s' failed\n", param_name, policy_str);
	}

	return result;
}
