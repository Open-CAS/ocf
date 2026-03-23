/*
 * Copyright(c) 2022-2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PREFETCH_READAHEAD_H__
#define __OCF_PREFETCH_READAHEAD_H__

#include "ocf_prefetch_priv.h"
#include "ocf/ocf_types.h"

void ocf_pf_readahead_get_range(struct ocf_request *req,
		struct ocf_pf_range *range);

#endif /* __OCF_PREFETCH_READAHEAD_H__ */
