/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "eviction.h"

struct eviction_policy_ops evict_policy_ops[ocf_eviction_max] = {
	[ocf_eviction_lru] = {
		.init_cline = evp_lru_init_cline,
		.rm_cline = evp_lru_rm_cline,
		.req_clines = evp_lru_req_clines,
		.hot_cline = evp_lru_hot_cline,
		.init_evp = evp_lru_init_evp,
		.dirty_cline = evp_lru_dirty_cline,
		.clean_cline = evp_lru_clean_cline,
		.name = "lru",
	},
};
