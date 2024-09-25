/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_inv.h"
#include "engine_common.h"
#include "cache_engine.h"
#include "../ocf_request.h"
#include "../utils/utils_cache_line.h"
#include "../metadata/metadata.h"
#include "../concurrency/ocf_concurrency.h"

#define OCF_ENGINE_DEBUG_IO_NAME "inv"
#include "engine_debug.h"

static void _ocf_invalidate_req(struct ocf_request *req, int error)
{
	OCF_DEBUG_RQ(req, "Completion");

	if (error) {
		ocf_core_stats_cache_error_update(req->core, OCF_WRITE);
		ocf_engine_error(req, true, "Failed to flush metadata to cache");
	}

	ocf_req_unlock_wr(ocf_cache_line_concurrency(req->cache), req);

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);
}

static int _ocf_invalidate_do(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	ocf_hb_req_prot_lock_wr(req);
	ocf_purge_map_info(req);
	ocf_hb_req_prot_unlock_wr(req);

	if (ocf_volume_is_atomic(&cache->device->volume) &&
			req->info.flush_metadata) {
		/* Metadata flush IO */
		ocf_metadata_flush_do_asynch(cache, req, _ocf_invalidate_req);
	} else {
		_ocf_invalidate_req(req, 0);
	}

	return 0;
}

void ocf_engine_invalidate(struct ocf_request *req)
{
	ocf_queue_push_req_cb(req, _ocf_invalidate_do,
			OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}
