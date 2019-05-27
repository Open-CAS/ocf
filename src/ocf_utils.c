/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_cache_priv.h"
#include "utils/utils_req.h"
#include "ocf_utils.h"
#include "ocf_ctx_priv.h"

int ocf_utils_init(struct ocf_ctx *ocf_ctx)
{
	return ocf_req_allocator_init(ocf_ctx);
}

void ocf_utils_deinit(struct ocf_ctx *ocf_ctx)
{
	ocf_req_allocator_deinit(ocf_ctx);
}
