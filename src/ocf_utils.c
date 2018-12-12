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
	int result;

	result = ocf_req_allocator_init(ocf_ctx);
	if (result)
		goto ocf_utils_init_ERROR;

	ocf_ctx->resources.core_io_allocator =
			env_allocator_create(sizeof(struct ocf_core_io),
					"ocf_io");
	if (!ocf_ctx->resources.core_io_allocator)
		goto ocf_utils_init_ERROR;

	return 0;

ocf_utils_init_ERROR:

	ocf_utils_deinit(ocf_ctx);

	return -1;
}

void ocf_utils_deinit(struct ocf_ctx *ocf_ctx)
{
	ocf_req_allocator_deinit(ocf_ctx);

	if (ocf_ctx->resources.core_io_allocator) {
		env_allocator_destroy(ocf_ctx->resources.core_io_allocator);
		ocf_ctx->resources.core_io_allocator = NULL;
	}
}
