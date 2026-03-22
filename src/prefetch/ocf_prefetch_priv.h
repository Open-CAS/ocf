/*
 * Copyright(c) 2022-2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PREFETCH_PRIV_H__
#define __OCF_PREFETCH_PRIV_H__

#include "ocf/ocf_prefetch.h"
#include "../ocf_request.h"
#include "ocf/ocf_types.h"
#include "ocf/ocf_def.h"

#define OCF_PF_MAX_TOTAL (8 * MiB)

#define OCF_PF_ID_VALID(pf_id) ((pf_id) != ocf_pf_none && (pf_id) < ocf_pf_num)
#define OCF_PF_ID_ENABLED(pf_id, enabled_mask) ((1 << ((pf_id))) & enabled_mask)

#define for_each_pf(pf_id) \
	for (pf_id = 0; pf_id < ocf_pf_num; pf_id++)

#define for_each_pf_mask(pf_id, pf_mask) \
	for_each_pf(pf_id) \
		if (OCF_PF_ID_ENABLED(pf_id, pf_mask))

struct ocf_pf_range {
	uint64_t core_line_first;
	uint32_t core_line_count;
};

void ocf_prefetch(struct ocf_request *req);
void ocf_prefetch_init(ocf_cache_t cache, ocf_core_t core);
void ocf_prefetch_deinit(ocf_cache_t cache, ocf_core_t core);
void ocf_prefetch_init_one(ocf_core_t core, ocf_pf_id_t pf_id);
void ocf_prefetch_deinit_one(ocf_core_t core, ocf_pf_id_t pf_id);

#endif /* __OCF_PREFETCH_PRIV_H__ */
