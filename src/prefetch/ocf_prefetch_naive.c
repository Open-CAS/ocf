/*
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf_prefetch_naive.h"
#include "ocf/ocf_def.h"

/* ===========================================================================*/
/* Read-ahead prefetchers */
void ocf_pf_readahead_get_info(ocf_prefetch_t pf, ocf_pf_req_info_t *req_info)
{
	req_info->pa_id = pa_id_readahead;
	req_info->addr += req_info->len;
}

void ocf_pf_skip1m_get_info(ocf_prefetch_t pf, ocf_pf_req_info_t *req_info)
{
	req_info->pa_id = pa_id_skip1m;
	req_info->addr += 1*MiB;
}

void ocf_pf_upper_get_info(ocf_prefetch_t pf, ocf_pf_req_info_t *req_info)
{
	req_info->pa_id = pa_id_none;
}
/* ===========================================================================*/
