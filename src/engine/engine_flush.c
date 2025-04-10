/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_common.h"
#include "engine_io.h"
#include "cache_engine.h"
#include "engine_flush.h"
#include "../ocf_request.h"

#define OCF_ENGINE_DEBUG_IO_NAME "flush"
#include "engine_debug.h"

static void _ocf_engine_flush_complete(struct ocf_request *req, int error)
{
	if (error)
		req->error = req->error ?: error;

	if (env_atomic_dec_return(&req->req_remaining))
		return;

	OCF_DEBUG_RQ(req, "Completion");

	if (req->error) {
		/* An error occured */
		ocf_engine_error(req, false, "Core operation failure");
	}

	/* Complete requests - both to cache and to core*/
	req->complete(req, req->error);

	/* Release OCF request */
	ocf_req_put(req);
}

int ocf_engine_flush(struct ocf_request *req)
{
	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	/* IO to the core device and to the cache device */
	env_atomic_set(&req->req_remaining, 2);

	/* Submit operation into core device */
	ocf_engine_forward_core_flush_req(req, _ocf_engine_flush_complete);

	/* submit flush to cache device */
	ocf_engine_forward_cache_flush_req(req, _ocf_engine_flush_complete);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}
