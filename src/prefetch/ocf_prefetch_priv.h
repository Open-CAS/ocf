/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PREFETCH_PRIV_H__
#define __OCF_PREFETCH_PRIV_H__

#include "ocf/ocf_types.h"
#include "ocf/ocf_prefetch_common.h"

typedef void *ocf_prefetch_t;

typedef struct {
	uint64_t addr;
	uint32_t len;
	pf_algo_id_t pa_id;
} ocf_pf_req_info_t;

#endif /* __OCF_PREFETCH_PRIV_H__ */
