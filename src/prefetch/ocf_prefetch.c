/*
 * Copyright(c) 2022-2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "../ocf_cache_priv.h"
#include "../ocf_core_priv.h"
#include "../ocf_def_priv.h"
#include "../ocf_request.h"
#include "../engine/engine_common.h"
#include "../engine/engine_prefetch.h"
#include "ocf_env.h"
#include "ocf_prefetch_priv.h"
#include "ocf_prefetch_readahead_priv.h"

struct ocf_pf_ops {
	void (*setup)(ocf_cache_t cache);
	int (*init)(ocf_core_t core);
	void (*deinit)(ocf_core_t core);
	void (*get_range)(struct ocf_request *req, struct ocf_pf_range *range);
	int (*set_param)(ocf_cache_t cache, uint32_t param_id,
			uint32_t param_value);
	int (*get_param)(ocf_cache_t cache, uint32_t param_id,
			uint32_t *param_value);
};

static struct ocf_pf_ops ocf_pf_ops[ocf_pf_num] = {
	[ocf_pf_readahead] = {
		.setup = ocf_pf_readahead_setup,
		.init = ocf_pf_readahead_init,
		.deinit = ocf_pf_readahead_deinit,
		.get_range = ocf_pf_readahead_get_range,
		.set_param = ocf_pf_readahead_set_param,
		.get_param = ocf_pf_readahead_get_param,
	},
};

static void _ocf_prefetch_complete(struct ocf_request *req, int error)
{
	ocf_req_put(req);
}

static bool ocf_pf_next_sub_range_miss(struct ocf_request *req,
		struct ocf_pf_range *range, struct ocf_pf_range *sub_range,
		uint32_t max_lines)
{
	ocf_cache_t cache = req->cache;
	ocf_core_id_t core_id = ocf_core_get_id(req->core);
	uint64_t curr, end;
	uint64_t first_miss, last_miss;

	curr = sub_range->core_line_first + sub_range->core_line_count;
	end = range->core_line_first + range->core_line_count;

	for (; curr < end; curr++) {
		if (!ocf_metadata_is_hit_no_lock(cache, core_id, curr))
			break;
	}

	if (curr >= end)
		return false;

	first_miss = curr;
	last_miss = curr;

	curr += 1;
	end = OCF_MIN(end, first_miss + max_lines);

	for (; curr < end; curr++) {
		if (ocf_metadata_is_hit_no_lock(cache, core_id, curr))
			break;

		last_miss = curr;
	}

	sub_range->core_line_first = first_miss;
	sub_range->core_line_count = last_miss - first_miss + 1;

	return true;
}

static void ocf_prefetch_range(struct ocf_request *req, ocf_pf_id_t pf_id,
		struct ocf_pf_range *range)
{
	struct ocf_request *prefetch_req = NULL;
	ocf_cache_t cache = req->cache;
	uint64_t volume_length_cl = ocf_bytes_2_lines(cache,
			ocf_volume_get_length(&req->core->volume));
	uint32_t max_total_cl = ocf_bytes_2_lines(cache, OCF_PF_MAX_TOTAL);
	struct ocf_pf_range sub_range = {
		.core_line_first = range->core_line_first,
		.core_line_count = 0,
	};
	uint32_t total_cl = 0, curmax_cl = 0;
	uint64_t addr;
	uint32_t bytes;

	if (unlikely(range->core_line_first >= volume_length_cl))
		return;

	range->core_line_count = OCF_MIN(range->core_line_count,
			volume_length_cl - range->core_line_first);

	curmax_cl = OCF_MIN(range->core_line_count, max_total_cl);
	while (ocf_pf_next_sub_range_miss(req, range, &sub_range, curmax_cl)) {
		addr = ocf_lines_2_bytes(cache, sub_range.core_line_first);
		bytes = ocf_lines_2_bytes(cache, sub_range.core_line_count);
		prefetch_req = ocf_req_new_extended(req->io_queue, req->core,
				addr, bytes, OCF_READ);
		if (unlikely(!prefetch_req))
			break;

		prefetch_req->io.io_class = OCF_IO_CLASS_PREFETCH;
		prefetch_req->io.pf_id = pf_id;

		prefetch_req->complete = _ocf_prefetch_complete;

		ocf_prefetch_read(prefetch_req);

		total_cl += sub_range.core_line_count;
		if (total_cl >= max_total_cl)
			break;

		curmax_cl = OCF_MIN(curmax_cl, max_total_cl - total_cl);
	}
}

void ocf_prefetch_setup(ocf_cache_t cache)
{
	ocf_pf_id_t pf_id;

	for_each_pf(pf_id) {
		if (ocf_pf_ops[pf_id].setup)
			ocf_pf_ops[pf_id].setup(cache);
	}
}

int ocf_prefetch_set_param(ocf_cache_t cache, ocf_pf_id_t pf_id,
		uint32_t param_id, uint32_t param_value)
{
	ENV_BUG_ON(!OCF_PF_ID_VALID(pf_id));

	if (!ocf_pf_ops[pf_id].set_param)
		return -OCF_ERR_INVAL;

	return ocf_pf_ops[pf_id].set_param(cache, param_id, param_value);
}

int ocf_prefetch_get_param(ocf_cache_t cache, ocf_pf_id_t pf_id,
		uint32_t param_id, uint32_t *param_value)
{
	ENV_BUG_ON(!OCF_PF_ID_VALID(pf_id));

	if (!ocf_pf_ops[pf_id].get_param)
		return -OCF_ERR_INVAL;

	return ocf_pf_ops[pf_id].get_param(cache, param_id, param_value);
}

void ocf_prefetch_init(ocf_cache_t cache, ocf_core_t core)
{
	ocf_pf_mask_t pf_mask = cache->conf_meta->prefetch_mask;
	ocf_pf_id_t pf_id;

	for_each_pf_mask(pf_id, pf_mask) {
		if (ocf_pf_ops[pf_id].init)
			ocf_pf_ops[pf_id].init(core);
	}
}

void ocf_prefetch_init_one(ocf_core_t core, ocf_pf_id_t pf_id)
{
	if (ocf_pf_ops[pf_id].init)
		ocf_pf_ops[pf_id].init(core);
}

void ocf_prefetch_deinit_one(ocf_core_t core, ocf_pf_id_t pf_id)
{
	if (ocf_pf_ops[pf_id].deinit)
		ocf_pf_ops[pf_id].deinit(core);
}

void ocf_prefetch_deinit(ocf_cache_t cache, ocf_core_t core)
{
	ocf_pf_mask_t pf_mask = cache->conf_meta->prefetch_mask;
	ocf_pf_id_t pf_id;

	for_each_pf_mask(pf_id, pf_mask) {
		if (ocf_pf_ops[pf_id].deinit)
			ocf_pf_ops[pf_id].deinit(core);
	}
}

void ocf_prefetch(struct ocf_request *req)
{
	ocf_pf_mask_t pf_mask = req->cache->conf_meta->prefetch_mask;
	struct ocf_pf_range ranges[ocf_pf_num] = {};
	ocf_pf_id_t pf_id;

	if (req->rw != OCF_READ)
		return;

	switch (req->cache_mode) {
	case ocf_req_cache_mode_pt:
	case ocf_req_cache_mode_wo:
		return;
	default:
		break;
	}

	for_each_pf_mask(pf_id, pf_mask)
		ocf_pf_ops[pf_id].get_range(req, &ranges[pf_id]);

	for_each_pf_mask(pf_id, pf_mask)
		ocf_prefetch_range(req, pf_id, &ranges[pf_id]);
}
