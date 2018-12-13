/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "metadata.h"
#include "metadata_hash.h"
#include "metadata_raw.h"
#include "metadata_raw_dynamic.h"
#include "metadata_io.h"
#include "../utils/utils_io.h"
#include "../ocf_def_priv.h"

#define OCF_METADATA_RAW_DEBUG  0

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
static bool _raw_ssd_page_is_valid(struct ocf_metadata_raw *raw, uint32_t page)
{
	ENV_BUG_ON(page < raw->ssd_pages_offset);
	ENV_BUG_ON(page >= (raw->ssd_pages_offset + raw->ssd_pages));

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

static void *_raw_dynamic_get_item(struct ocf_cache *cache,
	struct ocf_metadata_raw *raw, ocf_cache_line_t line, uint32_t size)
{
	void *new = NULL;
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;
	uint32_t page = _RAW_DYNAMIC_PAGE(raw, line);

	ENV_BUG_ON(!_raw_is_valid(raw, line, size));

	OCF_DEBUG_PARAM(cache, "Accessing item %u on page %u", line, page);

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

		new = env_zalloc(PAGE_SIZE, ENV_MEM_NORMAL);
		if (new) {
			ctrl->pages[page] = new;
			env_atomic_inc(&ctrl->count);
		}

_raw_dynamic_get_item_SKIP:

		env_mutex_unlock(&ctrl->lock);
	}

	if (ctrl->pages[page])
		return ctrl->pages[page] + _RAW_DYNAMIC_PAGE_OFFSET(raw, line);

	return NULL;
}

/*
* RAM DYNAMIC Implementation - De-Initialize
*/
int raw_dynamic_deinit(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	uint32_t i;
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;

	if (!ctrl)
		return 0;

	OCF_DEBUG_TRACE(cache);

	for (i = 0; i < raw->ssd_pages; i++)
		env_free(ctrl->pages[i]);

	env_vfree(ctrl);
	raw->priv = NULL;

	return 0;
}

/*
 * RAM DYNAMIC Implementation - Initialize
 */
int raw_dynamic_init(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	struct _raw_ctrl *ctrl;
	size_t size = sizeof(*ctrl) + (sizeof(ctrl->pages[0]) * raw->ssd_pages);

	OCF_DEBUG_TRACE(cache);

	if (raw->entry_size > PAGE_SIZE)
		return -1;

	ctrl = env_vmalloc(size);
	if (!ctrl)
		return -1;

	ENV_BUG_ON(env_memset(ctrl, size, 0));

	if (env_mutex_init(&ctrl->lock)) {
		env_vfree(ctrl);
		return -1;
	}

	raw->priv = ctrl;

	return 0;
}

/*
 * RAW DYNAMIC Implementation - Size of
 */
size_t raw_dynamic_size_of(struct ocf_cache *cache,
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
uint32_t raw_dynamic_size_on_ssd(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	const size_t alignment = 128 * KiB / PAGE_SIZE;

	return OCF_DIV_ROUND_UP(raw->ssd_pages, alignment) * alignment;
}

/*
 * RAM DYNAMIC Implementation - Checksum
 */
uint32_t raw_dynamic_checksum(struct ocf_cache *cache,
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
* RAM DYNAMIC Implementation - Get
*/
int raw_dynamic_get(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		void *data, uint32_t size)
{
	void *item = _raw_dynamic_get_item(cache, raw, line, size);

	if (!item) {
		ENV_BUG_ON(env_memset(data, size, 0));
		ocf_metadata_error(cache);
		return -1;
	}

	return env_memcpy(data, size, item, size);
}

/*
* RAM DYNAMIC Implementation - Set
*/
int raw_dynamic_set(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		void *data, uint32_t size)
{
	void *item = _raw_dynamic_get_item(cache, raw, line, size);

	if (!item) {
		ocf_metadata_error(cache);
		return -1;
	}

	return env_memcpy(item, size, data, size);
}

/*
* RAM DYNAMIC Implementation - access
*/
const void *raw_dynamic_rd_access(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		uint32_t size)
{
	return _raw_dynamic_get_item(cache, raw, line, size);
}

/*
* RAM DYNAMIC Implementation - access
*/
void *raw_dynamic_wr_access(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		uint32_t size)
{
	return _raw_dynamic_get_item(cache, raw, line, size);
}

int raw_dynamic_flush(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line)
{
	uint32_t page = _RAW_DYNAMIC_PAGE(raw, line);
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;

	OCF_DEBUG_PARAM(cache, "Line %u, page = %u", line, page);

	ENV_BUG_ON(!ctrl->pages[page]);

	return metadata_io_write(cache, ctrl->pages[page],
			raw->ssd_pages_offset + page);
}

/*
* RAM DYNAMIC Implementation - Load all
*/
#define RAW_DYNAMIC_LOAD_PAGES 128

int raw_dynamic_load_all(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;
	uint64_t i = 0, i_page = 0;
	uint64_t count = RAW_DYNAMIC_LOAD_PAGES;
	int error = 0, cmp;

	struct ocf_io *io;
	ctx_data_t *data = ctx_data_alloc(cache->owner, RAW_DYNAMIC_LOAD_PAGES);
	char *page = env_malloc(PAGE_SIZE, ENV_MEM_NORMAL);
	char *zpage = env_zalloc(PAGE_SIZE, ENV_MEM_NORMAL);

	if (!data || !page || !zpage) {
		ctx_data_free(cache->owner, data);
		env_free(page);
		env_free(zpage);
		return -ENOMEM;
	}

	OCF_DEBUG_TRACE(cache);

	/* Loading, need to load all metadata, when page is zero set, no need
	 * to allocate space for it
	 */

	while (i < raw->ssd_pages) {
		if (i + count > raw->ssd_pages)
			count = raw->ssd_pages - i;

		/* Allocate IO */
		io = ocf_new_cache_io(cache);
		if (!io) {
			error = -ENOMEM;
			break;
		}

		/* Setup IO */
		error = ocf_io_set_data(io, data, 0);
		if (error) {
			ocf_io_put(io);
			break;
		}
		ocf_io_configure(io,
			PAGES_TO_BYTES(raw->ssd_pages_offset + i),
			PAGES_TO_BYTES(count), OCF_READ, 0, 0);

		/* Submit IO */
		error = ocf_submit_io_wait(io);
		ocf_io_put(io);
		io = NULL;

		if (error)
			break;

		/* Reset head of data buffer */
		ctx_data_seek_check(cache->owner, data,
				ctx_data_seek_begin, 0);

		for (i_page = 0; i_page < count; i_page++, i++) {
			if (!page) {
				page = env_malloc(PAGE_SIZE, ENV_MEM_NORMAL);
				if (!page) {
					/* Allocation error */
					error = -ENOMEM;
					break;
				}
			}

			ctx_data_rd_check(cache->owner, page, data, PAGE_SIZE);

			error = env_memcmp(zpage, PAGE_SIZE, page,
					PAGE_SIZE, &cmp);
			if (error)
				break;

			if (cmp == 0) {
				OCF_DEBUG_PARAM(cache, "Zero loaded %llu", i);
				continue;
			}

			OCF_DEBUG_PARAM(cache, "Non-zero loaded %llu", i);

			ctrl->pages[i] = page;
			page = NULL;

			env_atomic_inc(&ctrl->count);
		}

		if (error)
			break;
	}

	env_free(zpage);
	env_free(page);
	ctx_data_free(cache->owner, data);

	return error;
}

/*
* RAM DYNAMIC Implementation - Flush all
*/
/*
 * RAM Implementation - Flush IO callback - Fill page
 */
static int _raw_dynamic_flush_all_fill(struct ocf_cache *cache,
		ctx_data_t *data, uint32_t page, void *context)
{
	uint32_t raw_page;
	struct ocf_metadata_raw *raw = (struct ocf_metadata_raw *)context;
	struct _raw_ctrl *ctrl = (struct _raw_ctrl *)raw->priv;

	ENV_BUG_ON(!_raw_ssd_page_is_valid(raw, page));

	raw_page = page - raw->ssd_pages_offset;

	if (ctrl->pages[raw_page]) {
		OCF_DEBUG_PARAM(cache, "Page = %u", raw_page);
		ctx_data_wr_check(cache->owner, data, ctrl->pages[raw_page],
				PAGE_SIZE);
	} else {
		OCF_DEBUG_PARAM(cache, "Zero fill, Page = %u", raw_page);
		/* Page was not allocated before set only zeros */
		ctx_data_zero_check(cache->owner, data, PAGE_SIZE);
	}

	return 0;
}

int raw_dynamic_flush_all(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	OCF_DEBUG_TRACE(cache);
	return metadata_io_write_i(cache, raw->ssd_pages_offset,
			raw->ssd_pages, _raw_dynamic_flush_all_fill, raw);
}

/*
 * RAM DYNAMIC Implementation - Mark to Flush
 */
void raw_dynamic_flush_mark(struct ocf_cache *cache, struct ocf_request *req,
		uint32_t map_idx, int to_state, uint8_t start, uint8_t stop)
{
	ENV_BUG();
}

/*
 * RAM DYNAMIC Implementation - Do flushing asynchronously
 */
int raw_dynamic_flush_do_asynch(struct ocf_cache *cache, struct ocf_request *req,
		struct ocf_metadata_raw *raw, ocf_req_end_t complete)
{
	ENV_BUG();
	return -ENOSYS;
}
