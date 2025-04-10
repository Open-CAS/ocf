/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_d2c.h"
#include "engine_common.h"
#include "engine_io.h"
#include "cache_engine.h"
#include "../ocf_request.h"
#include "../metadata/metadata.h"

#define OCF_ENGINE_DEBUG_IO_NAME "d2c"
#include "engine_debug.h"

static void _ocf_d2c_completion(struct ocf_request *req, int error)
{
	OCF_DEBUG_RQ(req, "Completion");

	if (error)
		ocf_core_stats_core_error_update(req->core, req->rw);

	/* Complete request */
	req->complete(req, error);

	/* Release OCF request */
	ocf_req_put(req);
}

int ocf_d2c_io_fast(struct ocf_request *req)
{
	OCF_DEBUG_TRACE(req->cache);

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	ocf_engine_forward_core_io_req(req, _ocf_d2c_completion);

	ocf_engine_update_block_stats(req);

	ocf_core_stats_pt_block_update(req->core, req->part_id, req->rw,
			req->bytes);

	ocf_core_stats_request_pt_update(req->core, req->part_id, req->rw,
			req->info.hit_no, req->core_line_count);

	return 0;
}

int ocf_d2c_flush_fast(struct ocf_request *req)
{
	OCF_DEBUG_TRACE(req->cache);

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	ocf_engine_forward_core_flush_req(req, _ocf_d2c_completion);

	ocf_engine_update_block_stats(req);

	ocf_core_stats_pt_block_update(req->core, req->part_id, req->rw,
			req->bytes);

	ocf_core_stats_request_pt_update(req->core, req->part_id, req->rw,
			req->info.hit_no, req->core_line_count);

	return 0;
}

int ocf_d2c_discard_fast(struct ocf_request *req)
{
	OCF_DEBUG_TRACE(req->cache);

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	ocf_engine_forward_core_discard_req(req, _ocf_d2c_completion);

	ocf_engine_update_block_stats(req);

	ocf_core_stats_pt_block_update(req->core, req->part_id, req->rw,
			req->bytes);

	ocf_core_stats_request_pt_update(req->core, req->part_id, req->rw,
			req->info.hit_no, req->core_line_count);

	return 0;
}
