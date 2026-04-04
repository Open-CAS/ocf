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
#include "ocf_prefetch_readahead.h"

struct ocf_pf_ops {
	void (*get_range)(struct ocf_request *req, struct ocf_pf_range *range);
};

static struct ocf_pf_ops ocf_pf_ops[ocf_pf_num] = {
	[ocf_pf_readahead] = {
		.get_range = ocf_pf_readahead_get_range,
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

		prefetch_req->io.io_class = PARTITION_PREFETCH;
		prefetch_req->io.pf_id = pf_id;

		prefetch_req->complete = _ocf_prefetch_complete;

		ocf_prefetch_read(prefetch_req);

		total_cl += sub_range.core_line_count;
		if (total_cl >= max_total_cl)
			break;

		curmax_cl = OCF_MIN(curmax_cl, max_total_cl - total_cl);
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
