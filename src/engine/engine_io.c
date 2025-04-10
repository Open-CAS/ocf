/*
 * Copyright(c) 2023 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "engine_io.h"
#include "engine_common.h"
#include "../ocf_priv.h"
#include "../ocf_cache_priv.h"
#include "../ocf_volume_priv.h"
#include "../ocf_request.h"
#include "../utils/utils_cache_line.h"

void ocf_engine_forward_cache_io(struct ocf_request *req, int dir,
		uint64_t offset, uint64_t size, ocf_req_end_t callback)
{
	ocf_cache_t cache = req->cache;
	uint32_t seek = req->addr % ocf_line_size(cache);
	uint32_t first_cl = ocf_bytes_2_lines(cache, offset + seek);
	uint64_t addr;

	req->cache_forward_end = callback;

	addr = cache->device->metadata_offset;
	addr += req->map[first_cl].coll_idx * ocf_line_size(cache);
	addr += (offset + seek) % ocf_line_size(cache);

	ocf_core_stats_cache_block_update(req->core, req->part_id,
			dir, req->bytes, req->io.pa_id);

	ocf_req_forward_cache_io(req, dir, addr, size,
			req->offset + offset);
}

void ocf_engine_forward_cache_io_req(struct ocf_request *req, int dir,
		ocf_req_end_t callback)
{
	ocf_cache_t cache = req->cache;
	uint64_t addr, bytes, total_bytes = 0, addr_next = 0;
	uint32_t i;

	req->cache_forward_end = callback;

	if (ocf_engine_is_sequential(req)) {
		addr = cache->device->metadata_offset;
		addr += req->map[0].coll_idx * ocf_line_size(cache);
		addr += req->addr % ocf_line_size(cache);

		ocf_core_stats_cache_block_update(req->core, req->part_id,
				dir, req->bytes, req->io.pa_id);

		ocf_req_forward_cache_io(req, dir, addr, req->bytes,
				req->offset);
		return;
	}

	ocf_req_forward_cache_get(req);
	for (i = 0; i < req->core_line_count; i++) {
		if (addr_next) {
			addr = addr_next;
		} else {
			addr  = req->map[i].coll_idx;
			addr *= ocf_line_size(cache);
			addr += cache->device->metadata_offset;
		}
		bytes = ocf_line_size(cache);

		if (i == 0) {
			uint64_t seek = (req->addr) %
					ocf_line_size(cache);

			addr += seek;
			bytes -= seek;
		}

		for (; i < (req->core_line_count - 1); i++) {
			addr_next = req->map[i + 1].coll_idx;
			addr_next *= ocf_line_size(cache);
			addr_next += cache->device->metadata_offset;

			if (addr_next != (addr + bytes))
				break;

			bytes += ocf_line_size(cache);
		}

		if (i == (req->core_line_count - 1)) {
			uint64_t skip = (ocf_line_size(cache) -
				((req->addr + req->bytes) %
				ocf_line_size(cache))) % ocf_line_size(cache);

			bytes -= skip;
		}

		bytes = OCF_MIN(bytes, req->bytes - total_bytes);
		ENV_BUG_ON(bytes == 0);

		ocf_core_stats_cache_block_update(req->core, req->part_id,
				dir, bytes, req->io.pa_id);

		ocf_req_forward_cache_io(req, dir, addr, bytes,
				req->offset + total_bytes);

		total_bytes += bytes;
	}

	ENV_BUG_ON(total_bytes != req->bytes);

	ocf_req_forward_cache_put(req);
}

void ocf_engine_forward_cache_flush_req(struct ocf_request *req,
		ocf_req_end_t callback)
{
	req->cache_forward_end = callback;

	ocf_req_forward_cache_flush(req);
}

void ocf_engine_forward_cache_discard_req(struct ocf_request *req,
		ocf_req_end_t callback)
{
	req->cache_forward_end = callback;

	ocf_req_forward_cache_discard(req, req->addr,
			req->bytes);
}

void ocf_engine_forward_core_io_req_func(struct ocf_request *req,
		ocf_req_end_t callback)
{
	ocf_core_stats_core_block_update(req->core, req->part_id, req->rw,
			req->bytes, req->io.pa_id);

	req->core_forward_end = callback;

	ocf_req_forward_core_io(req, req->rw, req->addr,
			req->bytes, req->offset);
}

void ocf_engine_forward_core_flush_req(struct ocf_request *req,
		ocf_req_end_t callback)
{
	ocf_core_stats_core_block_update(req->core, req->part_id, req->rw,
			req->bytes, req->io.pa_id);

	req->core_forward_end = callback;

	ocf_req_forward_core_flush(req);
}

void ocf_engine_forward_core_discard_req(struct ocf_request *req,
		ocf_req_end_t callback)
{
	ocf_core_stats_core_block_update(req->core, req->part_id, req->rw,
			req->bytes, req->io.pa_id);

	req->core_forward_end = callback;

	ocf_req_forward_core_discard(req, req->addr, req->bytes);
}
