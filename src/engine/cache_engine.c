/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../ocf_priv.h"
#include "../ocf_cache_priv.h"
#include "../ocf_queue_priv.h"
#include "../ocf_seq_cutoff.h"
#include "cache_engine.h"
#include "engine_common.h"
#include "engine_rd.h"
#include "engine_wt.h"
#include "engine_pt.h"
#include "engine_wi.h"
#include "engine_wa.h"
#include "engine_wb.h"
#include "engine_wo.h"
#include "engine_fast.h"
#include "engine_flush.h"
#include "engine_discard.h"
#include "../utils/utils_user_part.h"
#include "../ocf_request.h"
#include "../metadata/metadata.h"
#include "../ocf_space.h"
#include "ocf/ocf_blktrace.h"
#include "../classifier/ocf_classifier.h"

enum ocf_io_if_type {
	/* Public OCF IO interfaces to be set by user */
	OCF_IO_WT_IF,
	OCF_IO_WB_IF,
	OCF_IO_WA_IF,
	OCF_IO_WI_IF,
	OCF_IO_PT_IF,
	OCF_IO_WO_IF,
	OCF_IO_MAX_IF,

	/* Private OCF interfaces */
	OCF_IO_FAST_IF,
	OCF_IO_FLUSH_IF,
	OCF_IO_DISCARD_IF,
	OCF_IO_PRIV_MAX_IF,
};

static const struct ocf_io_if IO_IFS[OCF_IO_PRIV_MAX_IF] = {
	[OCF_IO_WT_IF] = {
		.cbs = {
			[OCF_READ] = ocf_read_generic,
			[OCF_WRITE] = ocf_write_wt,
		},
		.name = "Write Through"
	},
	[OCF_IO_WB_IF] = {
		.cbs = {
			[OCF_READ] = ocf_read_generic,
			[OCF_WRITE] = ocf_write_wb,
		},
		.name = "Write Back"
	},
	[OCF_IO_WA_IF] = {
		.cbs = {
			[OCF_READ] = ocf_read_generic,
			[OCF_WRITE] = ocf_write_wa,
		},
		.name = "Write Around"
	},
	[OCF_IO_WI_IF] = {
		.cbs = {
			[OCF_READ] = ocf_read_generic,
			[OCF_WRITE] = ocf_write_wi,
		},
		.name = "Write Invalidate"
	},
	[OCF_IO_PT_IF] = {
		.cbs = {
			[OCF_READ] = ocf_read_pt,
			[OCF_WRITE] = ocf_write_wi,
		},
		.name = "Pass Through",
	},
	[OCF_IO_WO_IF] = {
		.cbs = {
			[OCF_READ] = ocf_read_wo,
			[OCF_WRITE] = ocf_write_wb,
		},
		.name = "Write Only",
	},
	[OCF_IO_FAST_IF] = {
		.cbs = {
			[OCF_READ] = ocf_read_fast,
			[OCF_WRITE] = ocf_write_fast,
		},
		.name = "Fast",
	},
	[OCF_IO_FLUSH_IF] = {
		.cbs = {
			[OCF_READ] = ocf_engine_flush,
			[OCF_WRITE] = ocf_engine_flush,
		},
		.name = "Flush",
	},
	[OCF_IO_DISCARD_IF] = {
		.cbs = {
			[OCF_READ] = ocf_engine_discard,
			[OCF_WRITE] = ocf_engine_discard,
		},
		.name = "Discard",
	},
};

static const struct ocf_io_if *cache_mode_io_if_map[ocf_req_cache_mode_max] = {
	[ocf_req_cache_mode_wt] = &IO_IFS[OCF_IO_WT_IF],
	[ocf_req_cache_mode_wb] = &IO_IFS[OCF_IO_WB_IF],
	[ocf_req_cache_mode_wa] = &IO_IFS[OCF_IO_WA_IF],
	[ocf_req_cache_mode_wi] = &IO_IFS[OCF_IO_WI_IF],
	[ocf_req_cache_mode_wo] = &IO_IFS[OCF_IO_WO_IF],
	[ocf_req_cache_mode_pt] = &IO_IFS[OCF_IO_PT_IF],
	[ocf_req_cache_mode_fast] = &IO_IFS[OCF_IO_FAST_IF],
};

const char *ocf_get_io_iface_name(ocf_req_cache_mode_t cache_mode)
{
	if (cache_mode == ocf_req_cache_mode_max)
		return "Unknown";

	return cache_mode_io_if_map[cache_mode]->name;
}

ocf_req_cb ocf_cache_mode_to_engine_cb(
		ocf_req_cache_mode_t req_cache_mode, int rw)
{
	if (req_cache_mode == ocf_req_cache_mode_max)
		return NULL;

	return cache_mode_io_if_map[req_cache_mode]->cbs[rw];
}

bool ocf_fallback_pt_is_on(ocf_cache_t cache)
{
	int counter = env_atomic_read(&cache->fallback_pt_error_counter);
	int threshold = cache->fallback_pt_error_threshold;

	ENV_BUG_ON(counter < 0);

	return (threshold != OCF_CACHE_FALLBACK_PT_INACTIVE &&
			counter >= threshold);
}

void ocf_resolve_effective_cache_mode(ocf_cache_t cache,
		ocf_core_t core, struct ocf_request *req)
{
	if (ocf_fallback_pt_is_on(cache)){
		req->cache_mode = ocf_req_cache_mode_pt;
		return;
	}

	if (!ocf_req_is_4k(req->addr, req->bytes)) {
		req->cache_mode = ocf_req_cache_mode_pt;
		return;
	}

	if (req->core_line_count > ocf_cache_get_line_count(cache)) {
		req->cache_mode = ocf_req_cache_mode_pt;
		return;
	}

	if (ocf_core_seq_cutoff_check(core, req)) {
		req->cache_mode = ocf_req_cache_mode_pt;
		req->seq_cutoff = 1;
		return;
	}

	req->cache_mode = (ocf_req_cache_mode_t)ocf_user_part_get_cache_mode(cache,
				ocf_user_part_class2id(cache, req->part_id));
	if (!ocf_cache_mode_is_valid((ocf_cache_mode_t)req->cache_mode))
		req->cache_mode = (ocf_req_cache_mode_t)ocf_cache_get_mode(cache);

	ocf_classifier(req);

	if (req->rw == OCF_WRITE &&
	    ocf_req_cache_mode_has_lazy_write(req->cache_mode) &&
	    ocf_req_set_dirty(req)) {
		req->cache_mode = ocf_req_cache_mode_wt;
	}
}

int ocf_engine_hndl_req(struct ocf_request *req)
{
	ocf_cache_t cache = req->cache;

	OCF_CHECK_NULL(cache);

	req->engine_handler = ocf_cache_mode_to_engine_cb(req->cache_mode,
			req->rw);

	if (!req->engine_handler)
		return -OCF_ERR_INVAL;

	ocf_req_get(req);

	/* Till OCF engine is not synchronous fully need to push OCF request
	 * to into OCF workers
	 */

	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC);

	return 0;
}

int ocf_engine_hndl_fast_req(struct ocf_request *req)
{
	ocf_req_cb engine_cb;
	int ret;

	engine_cb = ocf_cache_mode_to_engine_cb(req->cache_mode, req->rw);
	if (!engine_cb)
		return -OCF_ERR_INVAL;

	ocf_req_get(req);

	ret = engine_cb(req);

	if (ret == OCF_FAST_PATH_NO)
		ocf_req_put(req);

	return ret;
}

void ocf_engine_hndl_discard_req(struct ocf_request *req)
{
	ocf_req_get(req);

	IO_IFS[OCF_IO_DISCARD_IF].cbs[req->rw](req);
}

void ocf_engine_hndl_flush_req(struct ocf_request *req)
{
	ocf_req_get(req);

	req->engine_handler = IO_IFS[OCF_IO_FLUSH_IF].cbs[req->rw];

	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC);
}

bool ocf_req_cache_mode_has_lazy_write(ocf_req_cache_mode_t mode)
{
	return ocf_cache_mode_is_valid((ocf_cache_mode_t)mode) &&
			ocf_mngt_cache_mode_has_lazy_write(
					(ocf_cache_mode_t)mode);
}
