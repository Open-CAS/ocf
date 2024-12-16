/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "alru.h"
#include "nop.h"
#include "acp.h"
#include "../metadata/metadata_superblock.h"
#include "../metadata/metadata_structs.h"
#include "../ocf_cache_priv.h"
#include "ocf_env_refcnt.h"

struct cleaning_policy_ops {
	void (*setup)(ocf_cache_t cache);
	int (*initialize)(ocf_cache_t cache, int init_metadata);
	void (*populate)(ocf_cache_t cache,
			ocf_cleaning_populate_end_t cmpl, void *priv);
	void (*deinitialize)(ocf_cache_t cache);
	int (*add_core)(ocf_cache_t cache, ocf_core_id_t core_id);
	void (*remove_core)(ocf_cache_t cache, ocf_core_id_t core_id);
	void (*init_cache_block)(ocf_cache_t cache, uint32_t cache_line);
	void (*purge_cache_block)(ocf_cache_t cache, uint32_t cache_line);
	int (*purge_range)(ocf_cache_t cache, int core_id,
			uint64_t start_byte, uint64_t end_byte);
	void (*set_hot_cache_line)(ocf_cache_t cache, uint32_t cache_line);
	int (*set_cleaning_param)(ocf_cache_t cache, uint32_t param_id,
			uint32_t param_value);
	int (*get_cleaning_param)(ocf_cache_t cache, uint32_t param_id,
			uint32_t *param_value);
	void (*perform_cleaning)(ocf_cache_t cache, ocf_cleaner_end_t cmpl);
	const char *name;
};


static struct cleaning_policy_ops cleaning_policy_ops[ocf_cleaning_max] = {
	[ocf_cleaning_nop] = {
		.name = "nop",
		.perform_cleaning = cleaning_nop_perform_cleaning,
	},
	[ocf_cleaning_alru] = {
		.setup = cleaning_policy_alru_setup,
		.init_cache_block = cleaning_policy_alru_init_cache_block,
		.purge_cache_block = cleaning_policy_alru_purge_cache_block,
		.purge_range = cleaning_policy_alru_purge_range,
		.set_hot_cache_line = cleaning_policy_alru_set_hot_cache_line,
		.initialize = cleaning_policy_alru_initialize,
		.populate = cleaning_policy_alru_populate,
		.deinitialize = cleaning_policy_alru_deinitialize,
		.set_cleaning_param = cleaning_policy_alru_set_cleaning_param,
		.get_cleaning_param = cleaning_policy_alru_get_cleaning_param,
		.perform_cleaning = cleaning_alru_perform_cleaning,
		.name = "alru",
	},
	[ocf_cleaning_acp] = {
		.setup = cleaning_policy_acp_setup,
		.init_cache_block = cleaning_policy_acp_init_cache_block,
		.purge_cache_block = cleaning_policy_acp_purge_block,
		.purge_range = cleaning_policy_acp_purge_range,
		.set_hot_cache_line = cleaning_policy_acp_set_hot_cache_line,
		.initialize = cleaning_policy_acp_initialize,
		.populate = cleaning_policy_acp_populate,
		.deinitialize = cleaning_policy_acp_deinitialize,
		.set_cleaning_param = cleaning_policy_acp_set_cleaning_param,
		.get_cleaning_param = cleaning_policy_acp_get_cleaning_param,
		.add_core = cleaning_policy_acp_add_core,
		.remove_core = cleaning_policy_acp_remove_core,
		.perform_cleaning = cleaning_policy_acp_perform_cleaning,
		.name = "acp",
	},
};

static inline void ocf_cleaning_setup(ocf_cache_t cache, ocf_cleaning_t policy)
{
	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].setup))
		return;

	cleaning_policy_ops[policy].setup(cache);
}

static inline int ocf_cleaning_initialize(ocf_cache_t cache,
		ocf_cleaning_t policy, int kick_cleaner)
{
	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].initialize))
		return 0;

	return cleaning_policy_ops[policy].initialize(cache, kick_cleaner);
}

static inline void ocf_cleaning_populate(ocf_cache_t cache,
		ocf_cleaning_t policy,
		ocf_cleaning_populate_end_t cmpl, void *priv)
{
	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].populate)) {
		cmpl(priv, 0);
		return;
	}

	cleaning_policy_ops[policy].populate(cache, cmpl, priv);
}

static inline void ocf_cleaning_deinitialize(ocf_cache_t cache)
{
	ocf_cleaning_t policy;

	policy = cache->cleaner.policy;

	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].deinitialize))
		return;

	cleaning_policy_ops[policy].deinitialize(cache);
}

static inline int ocf_cleaning_add_core(ocf_cache_t cache,
		ocf_core_id_t core_id)
{
	ocf_cleaning_t policy;
	int result = 0;

	if (unlikely(!env_refcnt_inc(&cache->cleaner.refcnt)))
		return -OCF_ERR_NO_LOCK;

	policy = cache->cleaner.policy;

	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].add_core))
		goto unlock;

	result = cleaning_policy_ops[policy].add_core(cache, core_id);

unlock:
	env_refcnt_dec(&cache->cleaner.refcnt);

	return result;
}

static inline void ocf_cleaning_remove_core(ocf_cache_t cache,
		ocf_core_id_t core_id)
{
	ocf_cleaning_t policy;

	if (unlikely(!env_refcnt_inc(&cache->cleaner.refcnt)))
		return;

	policy = cache->cleaner.policy;

	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].remove_core))
		goto unlock;

	cleaning_policy_ops[policy].remove_core(cache, core_id);

unlock:
	env_refcnt_dec(&cache->cleaner.refcnt);
}

static inline void ocf_cleaning_init_cache_block(ocf_cache_t cache,
		ocf_cache_line_t cache_line)
{
	ocf_cleaning_t policy;

	if (unlikely(!env_refcnt_inc(&cache->cleaner.refcnt)))
		return;

	policy = cache->cleaner.policy;
	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].init_cache_block))
		goto unlock;

	cleaning_policy_ops[policy].init_cache_block(cache, cache_line);

unlock:
	env_refcnt_dec(&cache->cleaner.refcnt);
}

static inline void ocf_cleaning_purge_cache_block(ocf_cache_t cache,
		ocf_cache_line_t cache_line)
{
	ocf_cleaning_t policy;

	if (unlikely(!env_refcnt_inc(&cache->cleaner.refcnt)))
		return;

	policy = cache->cleaner.policy;
	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].purge_cache_block))
		goto unlock;

	cleaning_policy_ops[policy].purge_cache_block(cache, cache_line);

unlock:
	env_refcnt_dec(&cache->cleaner.refcnt);
}

static inline void ocf_cleaning_purge_range(ocf_cache_t cache,
		ocf_core_id_t core_id, uint64_t start_byte, uint64_t end_byte)
{
	ocf_cleaning_t policy;

	if (unlikely(!env_refcnt_inc(&cache->cleaner.refcnt)))
		return;

	policy = cache->cleaner.policy;
	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].purge_range))
		goto unlock;

	cleaning_policy_ops[policy].purge_range(cache, core_id, start_byte,
			end_byte);

unlock:
	env_refcnt_dec(&cache->cleaner.refcnt);
}

static inline void ocf_cleaning_set_hot_cache_line(ocf_cache_t cache,
		ocf_cache_line_t cache_line)
{
	ocf_cleaning_t policy;

	if (unlikely(!env_refcnt_inc(&cache->cleaner.refcnt)))
		return;

	policy = cache->cleaner.policy;
	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].set_hot_cache_line))
		goto unlock;

	cleaning_policy_ops[policy].set_hot_cache_line(cache, cache_line);

unlock:
	env_refcnt_dec(&cache->cleaner.refcnt);
}

static inline int ocf_cleaning_set_param(ocf_cache_t cache,
		ocf_cleaning_t policy, uint32_t param_id, uint32_t param_value)
{
	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (!cleaning_policy_ops[policy].set_cleaning_param)
		return -OCF_ERR_INVAL;

	return cleaning_policy_ops[policy].set_cleaning_param(cache, param_id,
			param_value);
}

static inline int ocf_cleaning_get_param(ocf_cache_t cache,
		ocf_cleaning_t policy, uint32_t param_id, uint32_t *param_value)
{
	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (!cleaning_policy_ops[policy].get_cleaning_param)
		return -OCF_ERR_INVAL;

	return cleaning_policy_ops[policy].get_cleaning_param(cache, param_id,
			param_value);
}

static inline void ocf_cleaning_perform_cleaning(ocf_cache_t cache,
		ocf_cleaner_end_t cmpl)
{
	ocf_cleaning_t policy;

	if (unlikely(!env_refcnt_inc(&cache->cleaner.refcnt))) {
		cmpl(&cache->cleaner, 1000);
		return;
	}

	policy = cache->cleaner.policy;
	ENV_BUG_ON(policy >= ocf_cleaning_max);

	if (unlikely(!cleaning_policy_ops[policy].perform_cleaning)) {
		env_refcnt_dec(&cache->cleaner.refcnt);
		cmpl(&cache->cleaner, 1000);
		return;
	}

	cleaning_policy_ops[policy].perform_cleaning(cache, cmpl);

	env_refcnt_dec(&cache->cleaner.refcnt);
}

static inline const char *ocf_cleaning_get_name(ocf_cleaning_t policy)
{
	ENV_BUG_ON(!cleaning_policy_ops[policy].name);

	return cleaning_policy_ops[policy].name;
}
