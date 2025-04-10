/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Sequential length aware prefetch algorithm API
 * This *.h file should be included only by ocf_prefetch.c
 */

#ifndef __OCF_PREFETCH_STREAM_H__
#define __OCF_PREFETCH_STREAM_H__

#include "ocf_prefetch_priv.h"
#include "ocf/ocf_types.h"
#include "ocf/ocf_prefetch_common.h"

void ocf_pf_stream_create(ocf_core_t core);
void ocf_pf_stream_destroy(ocf_core_t core);
void ocf_pf_stream_get_info(ocf_prefetch_t pf, ocf_pf_req_info_t *req_info);

#endif /* __OCF_PREFETCH_STREAM_H__ */
