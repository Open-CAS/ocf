/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "metadata.h"
#include "metadata_io.h"
#include "metadata_segment_id.h"
#include "metadata_raw.h"
#include "metadata_raw_atomic.h"
#include "../utils/utils_io.h"
#include "../utils/utils_cache_line.h"
#include "../ocf_def_priv.h"

#define OCF_METADATA_RAW_ATOMIC_DEBUG 0

#if 1 == OCF_METADATA_RAW_ATOMIC_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Metadata][Raw][Atomic] %s\n", __func__)

#define OCF_DEBUG_MSG(cache, msg) \
	ocf_cache_log(cache, log_info, "[Metadata][Raw][Atomic] %s - %s\n", \
			__func__, msg)

#define OCF_DEBUG_PARAM(cache, format, ...) \
	ocf_cache_log(cache, log_info, "[Metadata][Raw][Atomic] %s - "format"\n", \
			__func__, ##__VA_ARGS__)
#else
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_MSG(cache, msg)
#define OCF_DEBUG_PARAM(cache, format, ...)
#endif

static void _raw_atomic_io_discard_cmpl(struct ocf_request *req, int error)
{
	ocf_req_end_t complete = req->priv;

	if (error)
		ocf_metadata_error(req->cache);

	/* Call metadata flush completed call back */
	OCF_DEBUG_MSG(ctx->req->cache, "Asynchronous flushing complete");

	complete(req, error);
}

static void _raw_atomic_io_discard_do(struct ocf_request *req,
		uint64_t start_addr, uint32_t len)
{
	ocf_cache_t cache = req->cache;

	OCF_DEBUG_PARAM(cache, "Page to flushing = %" ENV_PRIu64 ", count of pages = %u",
			start_addr, len);

	if (cache->device->volume.features.discard_zeroes)
		ocf_req_forward_cache_discard(req, start_addr, len);
	else
		ocf_req_forward_cache_write_zeros(req, start_addr, len);
}

void raw_atomic_flush_mark(struct ocf_cache *cache, struct ocf_request *req,
		uint32_t map_idx, int to_state, uint8_t start, uint8_t stop)
{
	if (to_state == INVALID) {
		req->map[map_idx].flush = true;
		req->map[map_idx].start_flush = start;
		req->map[map_idx].stop_flush = stop;
		req->info.flush_metadata = true;
	}
}

#define MAX_STACK_TAB_SIZE 32

static inline void _raw_atomic_add_page(struct ocf_cache *cache,
		uint32_t *clines_tab, uint64_t line, int *idx)
{
	clines_tab[*idx] = line;
	(*idx)++;
}

static void _raw_atomic_flush_do_asynch_sec(struct ocf_cache *cache,
		struct ocf_request *req, int map_idx)
{
	struct ocf_map_info *map = &req->map[map_idx];
	uint32_t len = 0;
	uint64_t start_addr;

	start_addr = map->coll_idx;
	start_addr *= ocf_line_size(cache);
	start_addr += cache->device->metadata_offset;

	start_addr += SECTORS_TO_BYTES(map->start_flush);
	len = SECTORS_TO_BYTES(map->stop_flush - map->start_flush);
	len += SECTORS_TO_BYTES(1);

	_raw_atomic_io_discard_do(req, start_addr, len);
}

int raw_atomic_flush_do_asynch(struct ocf_cache *cache, struct ocf_request *req,
		struct ocf_metadata_raw *raw, ocf_req_end_t complete)
{
	int result = 0, i;
	uint32_t __clines_tab[MAX_STACK_TAB_SIZE];
	uint32_t *clines_tab;
	int clines_to_flush = 0;
	uint32_t len = 0;
	int line_no = req->core_line_count;
	struct ocf_map_info *map;
	uint64_t start_addr;

	ENV_BUG_ON(!complete);

	if (!req->info.flush_metadata) {
		/* Nothing to flush call flush callback */
		complete(req, 0);
		return 0;
	}

	req->priv = complete;
	ocf_req_forward_cache_init(req, _raw_atomic_io_discard_cmpl);

	if (line_no == 1) {
		map = &req->map[0];
		if (map->flush && map->status != LOOKUP_MISS)
			_raw_atomic_flush_do_asynch_sec(cache, req, 0);
		else
			_raw_atomic_io_discard_cmpl(req, 0);
		return 0;
	}

	if (line_no <= MAX_STACK_TAB_SIZE) {
		clines_tab = __clines_tab;
	} else {
		clines_tab = env_zalloc(sizeof(*clines_tab) * line_no,
				ENV_MEM_NOIO);
		if (!clines_tab) {
			complete(req, -OCF_ERR_NO_MEM);
			return -OCF_ERR_NO_MEM;
		}
	}

	ocf_req_forward_cache_get(req);
	for (i = 0; i < line_no; i++) {
		map = &req->map[i];

		if (!map->flush || map->status == LOOKUP_MISS)
			continue;

		if (i == 0) {
			/* First */
			if (map->start_flush) {
				_raw_atomic_flush_do_asynch_sec(cache, req, i);
			} else {
				_raw_atomic_add_page(cache, clines_tab,
					map->coll_idx, &clines_to_flush);
			}
		} else if (i == (line_no - 1)) {
			/* Last */
			if (map->stop_flush != ocf_line_end_sector(cache)) {
				_raw_atomic_flush_do_asynch_sec(cache, req, i);
			} else {
				_raw_atomic_add_page(cache, clines_tab,
					map->coll_idx, &clines_to_flush);
			}
		} else {
			/* Middle */
			_raw_atomic_add_page(cache, clines_tab, map->coll_idx,
					&clines_to_flush);
		}

	}

	env_sort(clines_tab, clines_to_flush, sizeof(*clines_tab),
			_raw_ram_flush_do_page_cmp, NULL);

	i = 0;
	while (i < clines_to_flush) {
		start_addr = clines_tab[i];
		start_addr *= ocf_line_size(cache);
		start_addr += cache->device->metadata_offset;
		len = ocf_line_size(cache);

		while (true) {
			if ((i + 1) >= clines_to_flush)
				break;

			if ((clines_tab[i] + 1) != clines_tab[i + 1])
				break;

			i++;
			len += ocf_line_size(cache);
		}

		_raw_atomic_io_discard_do(req, start_addr, len);

		i++;
	}
	ocf_req_forward_cache_put(req);

	if (line_no > MAX_STACK_TAB_SIZE)
		env_free(clines_tab);

	return result;
}
