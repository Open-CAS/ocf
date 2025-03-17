/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024-2025 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "metadata.h"
#include "metadata_segment_id.h"
#include "metadata_raw.h"
#include "metadata_raw_dynamic.h"
#include "metadata_io.h"
#include "../engine/cache_engine.h"
#include "../engine/engine_common.h"
#include "../utils/utils_io.h"
#include "../ocf_request.h"
#include "../ocf_def_priv.h"
#include "../ocf_priv.h"

#define OCF_METADATA_RAW_DEBUG 0

#if 1 == OCF_METADATA_RAW_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Metadata][Volatile] %s\n", __func__)

#define OCF_DEBUG_PARAM(cache, format, ...) \
	ocf_cache_log(cache, log_info, "[Metadata][Volatile] %s - "format"\n", \
			__func__, ##__VA_ARGS__)
#else
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_PARAM(cache, format, ...)
#endif

/*******************************************************************************
 * Common RAW Implementation
 ******************************************************************************/

/*
 * Check if page is valid for specified RAW descriptor
 */

static uint32_t raw_dynamic_segment_size_on_ssd(struct ocf_metadata_raw *raw)
{
	const size_t alignment = 128 * KiB / PAGE_SIZE;

	return OCF_DIV_ROUND_UP(raw->ssd_pages, alignment) * alignment;
}

static bool _raw_ssd_page_is_valid(struct ocf_metadata_raw *raw, uint32_t page)
{
	uint32_t size = raw_dynamic_segment_size_on_ssd(raw) *
			(raw->flapping ? 2 : 1);

	ENV_BUG_ON(page < raw->ssd_pages_offset);
	ENV_BUG_ON(page >= (raw->ssd_pages_offset + size));

	return true;
}

/*******************************************************************************
 * RAW dynamic Implementation
 ******************************************************************************/

#define _RAW_DYNAMIC_PAGE(raw, line) \
		((line) / raw->entries_in_page)

#define _RAW_DYNAMIC_PAGE_OFFSET(raw, line) \
		((line % raw->entries_in_page) * raw->entry_size)

/*
 * RAW DYNAMIC control structure
 */
struct _raw_ctrl {
	env_mutex lock;
	env_atomic count;
	void *pages[];
};

static void *_raw_dynamic_get_item(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, uint32_t entry)
{
	void *new = NULL;
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;
	uint32_t page = _RAW_DYNAMIC_PAGE(raw, entry);

	ENV_BUG_ON(!_raw_is_valid(raw, entry));

	OCF_DEBUG_PARAM(cache, "Accessing item %u on page %u", entry, page);

	if (!ctrl->pages[page]) {
		/* No page, allocate one, and set*/

		/* This RAW container has some restrictions and need to check
		 * this limitation:
		 * 1. no atomic context when allocation
		 * 2. Only one allocator in time
		 */

		ENV_BUG_ON(env_in_interrupt());

		env_mutex_lock(&ctrl->lock);

		if (ctrl->pages[page]) {
			/* Page has been already allocated, skip allocation */
			goto _raw_dynamic_get_item_SKIP;
		}

		OCF_DEBUG_PARAM(cache, "New page allocation - %u", page);

		new = env_secure_alloc(PAGE_SIZE);
		if (new) {
			ENV_BUG_ON(env_memset(new, PAGE_SIZE, 0));
			ctrl->pages[page] = new;
			env_atomic_inc(&ctrl->count);
		}

_raw_dynamic_get_item_SKIP:

		env_mutex_unlock(&ctrl->lock);
	}

	if (ctrl->pages[page])
		return ctrl->pages[page] + _RAW_DYNAMIC_PAGE_OFFSET(raw, entry);

	return NULL;
}

/*
* RAM DYNAMIC Implementation - De-Initialize
*/
int raw_dynamic_deinit(ocf_cache_t cache,
		struct ocf_metadata_raw *raw)
{
	uint32_t i;
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;

	if (!ctrl)
		return 0;

	OCF_DEBUG_TRACE(cache);

	ocf_mio_concurrency_deinit(&raw->mio_conc);

	for (i = 0; i < raw->ssd_pages; i++)
		env_secure_free(ctrl->pages[i], PAGE_SIZE);

	env_mutex_destroy(&ctrl->lock);

	env_vfree(ctrl);
	raw->priv = NULL;

	return 0;
}

/*
 * RAM DYNAMIC Implementation - Initialize
 */
int raw_dynamic_init(ocf_cache_t cache,
		ocf_flush_page_synch_t lock_page_pfn,
		ocf_flush_page_synch_t unlock_page_pfn,
		struct ocf_metadata_raw *raw)
{
	struct _raw_ctrl *ctrl;
	size_t size = sizeof(*ctrl) + (sizeof(ctrl->pages[0]) * raw->ssd_pages);
	int ret;

	OCF_DEBUG_TRACE(cache);

	if (raw->entry_size > PAGE_SIZE)
		return -1;

	/* TODO: caller should specify explicitly whether to init mio conc? */
	if (lock_page_pfn) {
		ret = ocf_mio_concurrency_init(&raw->mio_conc,
			raw->ssd_pages_offset, raw->ssd_pages, cache);
		if (ret)
			return ret;
	}
	ctrl = env_vmalloc(size);
	if (!ctrl) {
		ocf_mio_concurrency_deinit(&raw->mio_conc);
		return -1;
	}

	ENV_BUG_ON(env_memset(ctrl, size, 0));

	if (env_mutex_init(&ctrl->lock)) {
		ocf_mio_concurrency_deinit(&raw->mio_conc);
		env_vfree(ctrl);
		return -1;
	}

	raw->priv = ctrl;

	raw->lock_page = lock_page_pfn;
	raw->unlock_page = unlock_page_pfn;

	return 0;
}

/*
 * RAW DYNAMIC Implementation - Size of
 */
size_t raw_dynamic_size_of(ocf_cache_t cache,
		struct ocf_metadata_raw *raw)
{
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;
	size_t size;

	/* Size of allocated items */
	size = env_atomic_read(&ctrl->count);
	size *= PAGE_SIZE;

	/* Size of control structure */
	size += sizeof(*ctrl) + (sizeof(ctrl->pages[0]) * raw->ssd_pages);

	OCF_DEBUG_PARAM(cache, "Count = %d, Size = %lu",
			env_atomic_read(&ctrl->count), size);

	return size;
}

/*
 * RAW DYNAMIC Implementation - Size on SSD
 */
uint32_t raw_dynamic_size_on_ssd(struct ocf_metadata_raw *raw)
{
	size_t flapping_factor = raw->flapping ? 2 : 1;

	return raw_dynamic_segment_size_on_ssd(raw) * flapping_factor;
}

/*
 * RAM DYNAMIC Implementation - Checksum
 */
uint32_t raw_dynamic_checksum(ocf_cache_t cache,
		struct ocf_metadata_raw *raw)
{
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;
	uint64_t i;
	uint32_t step = 0;
	uint32_t crc = 0;

	for (i = 0; i < raw->ssd_pages; i++) {
		if (ctrl->pages[i])
			crc = env_crc32(crc, ctrl->pages[i], PAGE_SIZE);
		OCF_COND_RESCHED(step, 10000);
	}

	return crc;
}

/*
 * RAM DYNAMIC Implementation - Entry page number
 */
uint32_t raw_dynamic_page(struct ocf_metadata_raw *raw, uint32_t entry)
{
	ENV_BUG_ON(entry >= raw->entries);

	return _RAW_DYNAMIC_PAGE(raw, entry);
}

/*
* RAM DYNAMIC Implementation - access
*/
void *raw_dynamic_access(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, uint32_t entry)
{
	return _raw_dynamic_get_item(cache, raw, entry);
}

/*
 * RAM DYNAMIC Implementation - update
 */
static int raw_dynamic_update_pages(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, ctx_data_t *data, uint64_t page,
		uint64_t count, uint8_t **buffer, uint8_t *zpage)
{
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;
	int result = 0;
	uint64_t i;
	int cmp;

	for (i = 0; i < count; i++) {
		if (!*buffer) {
			*buffer = env_secure_alloc(PAGE_SIZE);
			if (!*buffer)
				return -OCF_ERR_NO_MEM;
		}

		ctx_data_rd_check(cache->owner, *buffer, data, PAGE_SIZE);

		result = env_memcmp(zpage, PAGE_SIZE, *buffer, PAGE_SIZE, &cmp);
		if (result < 0)
			return result;

		/* When page is zero set, no need to allocate space for it */
		if (cmp == 0) {
			OCF_DEBUG_PARAM(cache, "Zero loaded %llu", i);
			if (ctrl->pages[page + i]) {
				env_secure_free(ctrl->pages[page + i],
						PAGE_SIZE);
				ctrl->pages[page + i] = NULL;
				env_atomic_dec(&ctrl->count);
			}
			continue;
		}

		OCF_DEBUG_PARAM(cache, "Non-zero loaded %llu", i);

		if (ctrl->pages[page + i])
			env_secure_free(ctrl->pages[page + i], PAGE_SIZE);
		ctrl->pages[page + i] = *buffer;
		*buffer = NULL;

		env_atomic_inc(&ctrl->count);
	}

	return 0;
}

int raw_dynamic_update(ocf_cache_t cache,
		struct ocf_metadata_raw *raw, ctx_data_t *data,
		uint64_t page, uint64_t count)
{
	uint8_t *buffer = NULL, *zpage;
	int result;

	zpage = env_vzalloc(PAGE_SIZE);
	if (!zpage)
		return -OCF_ERR_NO_MEM;

	result = raw_dynamic_update_pages(cache, raw, data, page,
			count, &buffer, zpage);

	if (buffer)
		env_secure_free(buffer, PAGE_SIZE);

	env_vfree(zpage);

	return result;
}

/*
* RAM DYNAMIC Implementation - Load all
*/
#define RAW_DYNAMIC_LOAD_PAGES 128
#define metadata_io_size(__i_page, __pages_total) \
	OCF_MIN(RAW_DYNAMIC_LOAD_PAGES, (__pages_total -__i_page))

struct raw_dynamic_load_all_context {
	struct ocf_metadata_raw *raw;
	unsigned flapping_idx;
	struct ocf_request *req;
	ocf_cache_t cache;
	uint8_t *zpage;
	uint8_t *page;
	uint64_t i_page;
	int error;

	ocf_metadata_end_t cmpl;
	void *priv;
};

static void raw_dynamic_load_all_complete(
		struct raw_dynamic_load_all_context *context, int error)
{
	context->cmpl(context->priv, error);

	env_secure_free(context->page, PAGE_SIZE);
	env_free(context->zpage);
	ctx_data_free(context->cache->owner, context->req->data);
	ocf_req_put(context->req);
	env_vfree(context);
}

static int raw_dynamic_load_all_update(struct ocf_request *req);

static void raw_dynamic_load_all_read_end(struct ocf_request *req, int error)
{
	struct raw_dynamic_load_all_context *context = req->priv;

	if (error) {
		raw_dynamic_load_all_complete(context, error);
		return;
	}

	context->req->engine_handler = raw_dynamic_load_all_update;
	ocf_queue_push_req(req,
			OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

static int raw_dynamic_load_all_read(struct ocf_request *req)
{
	struct raw_dynamic_load_all_context *context = req->priv;
	struct ocf_metadata_raw *raw = context->raw;
	uint64_t ssd_pages_offset;
	uint64_t count;

	ssd_pages_offset = raw->ssd_pages_offset +
			raw_dynamic_segment_size_on_ssd(raw) *
					context->flapping_idx;

	count = metadata_io_size(context->i_page, raw->ssd_pages);

	ocf_req_forward_cache_init(req, raw_dynamic_load_all_read_end);

	ocf_req_forward_cache_io(req, OCF_READ,
			PAGES_TO_BYTES(ssd_pages_offset + context->i_page),
			PAGES_TO_BYTES(count), 0);

	return 0;
}

static int raw_dynamic_load_all_update(struct ocf_request *req)
{
	struct raw_dynamic_load_all_context *context = req->priv;
	struct ocf_metadata_raw *raw = context->raw;
	ocf_cache_t cache = context->cache;
	uint64_t count = metadata_io_size(context->i_page, raw->ssd_pages);
	int result = 0;

	/* Reset head of data buffer */
	ctx_data_seek_check(context->cache->owner, req->data,
			ctx_data_seek_begin, 0);

	result = raw_dynamic_update_pages(cache, raw, req->data,
			context->i_page, count, &context->page, context->zpage);

	context->i_page += count;

	if (result || context->i_page >= raw->ssd_pages) {
		raw_dynamic_load_all_complete(context, result);
		return 0;
	}

	context->req->engine_handler = raw_dynamic_load_all_read;
	ocf_queue_push_req(context->req,
			OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);

	return 0;
}

void raw_dynamic_load_all(ocf_cache_t cache, struct ocf_metadata_raw *raw,
		ocf_metadata_end_t cmpl, void *priv, unsigned flapping_idx)
{
	struct raw_dynamic_load_all_context *context;
	struct ocf_request *req;
	int result;

	ENV_BUG_ON(raw->flapping ? flapping_idx > 1 : flapping_idx != 0);
	OCF_DEBUG_TRACE(cache);

	context = env_vzalloc(sizeof(*context));
	if (!context)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	context->raw = raw;
	context->flapping_idx = flapping_idx;
	context->cache = cache;
	context->cmpl = cmpl;
	context->priv = priv;

	context->zpage = env_zalloc(PAGE_SIZE, ENV_MEM_NORMAL);
	if (!context->zpage) {
		result = -OCF_ERR_NO_MEM;
		goto err_zpage;
	}

	req = ocf_req_new_mngt(cache, cache->mngt_queue);
	if (!req) {
		result = -OCF_ERR_NO_MEM;
		goto err_req;
	}

	req->data = ctx_data_alloc(cache->owner, RAW_DYNAMIC_LOAD_PAGES);
	if (!req->data) {
		result = -OCF_ERR_NO_MEM;
		goto err_data;
	}

	req->info.internal = true;
	req->priv = context;
	req->engine_handler = raw_dynamic_load_all_read;

	context->req = req;

	ocf_queue_push_req(context->req,
			OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
	return;

err_data:
	ocf_req_put(req);
err_req:
	env_free(context->zpage);
err_zpage:
	env_vfree(context);
	OCF_CMPL_RET(priv, result);
}

/*
 * RAM DYNAMIC Implementation - Flush all
 */

struct raw_dynamic_flush_all_context {
	struct ocf_metadata_raw *raw;
	uint64_t ssd_pages_offset;
	ocf_metadata_end_t cmpl;
	void *priv;
};

/*
 * RAM Implementation - Flush IO callback - Fill page
 */
static int raw_dynamic_flush_all_fill(ocf_cache_t cache,
		ctx_data_t *data, uint32_t page, void *priv)
{
	struct raw_dynamic_flush_all_context *context = priv;
	struct ocf_metadata_raw *raw = context->raw;
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;
	uint32_t raw_page;

	ENV_BUG_ON(!_raw_ssd_page_is_valid(raw, page));

	raw_page = page - context->ssd_pages_offset;

	if (ctrl->pages[raw_page]) {
		OCF_DEBUG_PARAM(cache, "Page = %u", raw_page);
		if (raw->lock_page)
			raw->lock_page(cache, raw, raw_page);
		ctx_data_wr_check(cache->owner, data, ctrl->pages[raw_page],
				PAGE_SIZE);
		if (raw->unlock_page)
			raw->unlock_page(cache, raw, raw_page);
	} else {
		OCF_DEBUG_PARAM(cache, "Zero fill, Page = %u", raw_page);
		/* Page was not allocated before set only zeros */
		ctx_data_zero_check(cache->owner, data, PAGE_SIZE);
	}

	return 0;
}

static void raw_dynamic_flush_all_complete(ocf_cache_t cache,
		void *priv, int error)
{
	struct raw_dynamic_flush_all_context *context = priv;

	context->cmpl(context->priv, error);
	env_vfree(context);
}

void raw_dynamic_flush_all(ocf_cache_t cache, struct ocf_metadata_raw *raw,
		ocf_metadata_end_t cmpl, void *priv, unsigned flapping_idx)
{
	struct raw_dynamic_flush_all_context *context;
	int result;

	ENV_BUG_ON(raw->flapping ? flapping_idx > 1 : flapping_idx != 0);
	OCF_DEBUG_TRACE(cache);

	context = env_vmalloc(sizeof(*context));
	if (!context)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	context->raw = raw;
	context->cmpl = cmpl;
	context->priv = priv;
	context->ssd_pages_offset = raw->ssd_pages_offset +
			raw_dynamic_segment_size_on_ssd(raw) * flapping_idx;

	result = metadata_io_write_i_asynch(cache, cache->mngt_queue, context,
			context->ssd_pages_offset, raw->ssd_pages, 0,
			raw_dynamic_flush_all_fill,
			raw_dynamic_flush_all_complete,
			raw->mio_conc);
	if (result)
		OCF_CMPL_RET(priv, result);
}

/*
 * RAM DYNAMIC Implementation - Mark to Flush
 */
void raw_dynamic_flush_mark(ocf_cache_t cache, struct ocf_request *req,
		uint32_t map_idx, int to_state, uint8_t start, uint8_t stop)
{
	ENV_BUG();
}

/*
 * RAM DYNAMIC Implementation - Do flushing asynchronously
 */
int raw_dynamic_flush_do_asynch(ocf_cache_t cache, struct ocf_request *req,
		struct ocf_metadata_raw *raw, ocf_req_end_t complete)
{
	ENV_BUG();
	return -OCF_ERR_NOT_SUPP;
}
