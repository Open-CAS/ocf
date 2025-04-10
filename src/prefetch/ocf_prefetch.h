/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PREFETCH_H__
#define __OCF_PREFETCH_H__

#include "ocf/ocf_types.h"
#include "../ocf_request.h"

void ocf_prefetch_create(ocf_core_t core);
void ocf_prefetch_destroy(ocf_core_t core);
void ocf_prefetch(struct ocf_request *req);

#endif /* __OCF_PREFETCH_H__ */
