/*
 * Copyright(c) 2022-2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PREFETCH_READAHEAD_PRIV_H__
#define __OCF_PREFETCH_READAHEAD_PRIV_H__

#include "ocf_prefetch_priv.h"
#include "ocf/ocf_types.h"
#include "ocf_env.h"

struct readahead_prefetch_policy_config {
	uint32_t threshold;	/* in bytes */
};

void ocf_pf_readahead_setup(ocf_cache_t cache);
int ocf_pf_readahead_init(ocf_core_t core);
void ocf_pf_readahead_deinit(ocf_core_t core);
void ocf_pf_readahead_get_range(struct ocf_request *req,
		struct ocf_pf_range *range);
int ocf_pf_readahead_set_param(ocf_cache_t cache, uint32_t param_id,
		uint32_t param_value);
int ocf_pf_readahead_get_param(ocf_cache_t cache, uint32_t param_id,
		uint32_t *param_value);

#endif /* __OCF_PREFETCH_READAHEAD_PRIV_H__ */
