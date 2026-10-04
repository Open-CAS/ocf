/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_CLEANING_POLICY_H__
#define __METADATA_CLEANING_POLICY_H__

#include "ocf/ocf.h"

/* Cleaning policy metadata per partition */

struct nop_cleaning_policy {
};

struct alru_cleaning_policy {
	env_atomic size;
	uint32_t lru_head;
	uint32_t lru_tail;
};

struct acp_cleaning_policy {
};

struct cleaning_policy {
	union {
		struct nop_cleaning_policy nop;
		struct alru_cleaning_policy alru;
		struct acp_cleaning_policy acp;
	} policy;
};
struct cleaning_policy_meta *
ocf_metadata_get_cleaning_policy(struct ocf_cache *cache,
		ocf_cache_line_t line);


#endif /* METADATA_CLEANING_POLICY_H_ */
