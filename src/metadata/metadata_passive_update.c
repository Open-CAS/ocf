/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024-2025 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"

#include "metadata.h"
#include "metadata_passive_update.h"
#include "metadata_collision.h"
#include "metadata_segment_id.h"
#include "metadata_internal.h"
#include "metadata_io.h"
#include "metadata_raw.h"
#include "metadata_segment.h"
#include "../concurrency/ocf_concurrency.h"
#include "../ocf_def_priv.h"
#include "../ocf_priv.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_io.h"
#include "../utils/utils_pipeline.h"
#include "../concurrency/ocf_pio_concurrency.h"
#include "../engine/engine_common.h"

#define MAX_PASSIVE_IO_SIZE (32*MiB)

static int passive_io_resume(struct ocf_request *req)
{
	struct ocf_request *master = req->master_io_req;
	ocf_cache_t cache = req->cache;
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	uint64_t io_start_page = BYTES_TO_PAGES(master->addr);
	uint64_t io_pages_count = BYTES_TO_PAGES(master->bytes);
	uint64_t io_end_page = io_start_page + io_pages_count - 1;
	enum ocf_metadata_segment_id update_segments[] = {
		metadata_segment_sb_config,
		metadata_segment_collision,
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(update_segments); i++) {
		enum ocf_metadata_segment_id seg = update_segments[i];
		struct ocf_metadata_raw *raw = &(ctrl->raw_desc[seg]);
		uint64_t raw_start_page = raw->ssd_pages_offset;
		uint64_t raw_end_page = raw_start_page + raw->ssd_pages - 1;
		uint64_t overlap_start = OCF_MAX(io_start_page, raw_start_page);
		uint64_t overlap_end = OCF_MIN(io_end_page, raw_end_page);
		uint64_t overlap_start_data = overlap_start - io_start_page;
		uint64_t overlap_page;
		uint64_t overlap_count;

		if (overlap_start > overlap_end)
			continue;

		overlap_page = overlap_start - raw_start_page;
		overlap_count = overlap_end - overlap_start + 1;

		ctx_data_seek(cache->owner, req->data, ctx_data_seek_begin,
				PAGES_TO_BYTES(overlap_start_data));
		ocf_metadata_raw_update(cache, raw, req->data, overlap_page,
				overlap_count);
	}

	ocf_pio_async_unlock(req->cache->standby.concurrency, req);
	master->complete(master, 0);
	env_allocator_del(cache->standby.allocator, req);
	return 0;
}

static void passive_io_page_lock_acquired(struct ocf_request *req)
{
	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

int ocf_metadata_passive_update(struct ocf_request *master)
{
	ocf_cache_t cache = master->cache;
	uint64_t io_start_page = BYTES_TO_PAGES(master->addr);
	uint64_t io_end_page = io_start_page + BYTES_TO_PAGES(master->bytes);
	struct ocf_request *req;
	int lock = 0;

	if (master->rw == OCF_READ) {
		master->complete(master, 0);
		return 0;
	}

	if (io_start_page >= ocf_metadata_get_pages_count(cache)) {
		master->complete(master, 0);
		return 0;
	}

	if (master->addr % PAGE_SIZE || master->bytes % PAGE_SIZE) {
		ocf_cache_log(cache, log_warn,
				"Metadata update not aligned to page size!\n");
		master->complete(master, -OCF_ERR_INVAL);
		return -OCF_ERR_INVAL;
	}

	if (master->bytes > MAX_PASSIVE_IO_SIZE) {
		//FIXME handle greater IOs
		ocf_cache_log(cache, log_warn,
				"IO size exceedes max supported size!\n");
		master->complete(master, -OCF_ERR_INVAL);
		return -OCF_ERR_INVAL;
	}

	req = (struct ocf_request*)env_allocator_new(cache->standby.allocator);
	if (!req) {
		master->complete(master, -OCF_ERR_NO_MEM);
		return -OCF_ERR_NO_MEM;
	}

	req->io_queue = master->io_queue;;
	req->info.internal = true;
	req->engine_handler = passive_io_resume;
	req->rw = OCF_WRITE;
	req->master_io_req = master;
	req->data = master->data;
	req->cache = cache;
	env_atomic_set(&req->lock_remaining, 0);

	req->core_line_first = io_start_page;
	req->core_line_count = io_end_page - io_start_page;
	req->alock_status = (uint8_t*)&req->map;

	lock = ocf_pio_async_lock(req->cache->standby.concurrency,
			req, passive_io_page_lock_acquired);
	if (lock < 0) {
		env_allocator_del(cache->standby.allocator, req);
		master->complete(master, lock);
		return lock;
	}

	if (lock == OCF_LOCK_ACQUIRED)
		passive_io_resume(req);

	return 0;
}

int ocf_metadata_passive_io_ctx_init(ocf_cache_t cache)
{
	char *name = "ocf_cache_pio";
	size_t element_size, header_size, size;

	header_size = sizeof(struct ocf_request);
	/* Only one bit per page is required. Since `alock_status` has `uint8_t*`
	   type, one entry can carry status for 8 pages. */
	element_size = OCF_DIV_ROUND_UP(BYTES_TO_PAGES(MAX_PASSIVE_IO_SIZE), 8);
	size = header_size + element_size;

	cache->standby.allocator = env_allocator_create(size, name, true);
	if (cache->standby.allocator == NULL)
		return -1;

	return 0;
}

void ocf_metadata_passive_io_ctx_deinit(ocf_cache_t cache)
{
	env_allocator_destroy(cache->standby.allocator);
}
