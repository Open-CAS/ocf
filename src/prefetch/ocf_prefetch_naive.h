/*
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PREFETCH_NAIVE_H__
#define __OCF_PREFETCH_NAIVE_H__

#include "ocf_prefetch_priv.h"
#include "ocf/ocf_types.h"
#include "ocf/ocf_prefetch_common.h"

void ocf_pf_readahead_get_info(ocf_prefetch_t pf, ocf_pf_req_info_t *req_info);
void ocf_pf_skip1m_get_info(ocf_prefetch_t pf, ocf_pf_req_info_t *req_info);
void ocf_pf_upper_get_info(ocf_prefetch_t pf, ocf_pf_req_info_t *req_info);

#endif /* __OCF_PREFETCH_NAIVE_H__ */
