/*
 * Copyright(c) 2022-2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf_prefetch_readahead.h"
#include "../utils/utils_cache_line.h"
#include "ocf/ocf_def.h"

#define OCF_PF_READAHEAD_MIN (64 * KiB)

/*
 * NOTE: This simplistic implementation is meant to serve as an reference
 *       implementation for other prefetch policies. In the current form
 *       it's not expected to bring any performance improvements for most
 *       of the workloads (actually it's expected to cause performance
 *       degratation in most cases).
 */
void ocf_pf_readahead_get_range(struct ocf_request *req,
		struct ocf_pf_range *range)
{
	range->core_line_first = req->core_line_first + req->core_line_count;
	range->core_line_count = OCF_MAX(req->core_line_count,
			ocf_bytes_2_lines(req->cache, OCF_PF_READAHEAD_MIN));
}
