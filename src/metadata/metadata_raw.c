/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "metadata.h"
#include "metadata_hash.h"
#include "metadata_raw.h"
#include "metadata_io.h"
#include "metadata_raw_atomic.h"
#include "../ocf_def_priv.h"

#define OCF_METADATA_RAW_DEBUG 0

#if 1 == OCF_METADATA_RAW_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(log_info, "[Metadata][Raw] %s\n", __func__)

#define OCF_DEBUG_MSG(cache, msg) \
	ocf_cache_log(cache, log_info, "[Metadata][Raw] %s - %s\n", \
			__func__, msg)

#define OCF_DEBUG_PARAM(cache, format, ...) \
	ocf_cache_log(cache, log_info, "[Metadata][Raw] %s - "format"\n", \
			__func__, ##__VA_ARGS__)
#else
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_MSG(cache, msg)
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
 * RAW RAM Implementation
 ******************************************************************************/
#define _RAW_RAM_ADDR(raw, line) \
	(raw->mem_pool + (((uint64_t)raw->entry_size * (line))))

#define _RAW_RAM_PAGE(raw, line) \
		((line) / raw->entries_in_page)

#define _RAW_RAM_PAGE_SSD(raw, line) \
		(raw->ssd_pages_offset + _RAW_RAM_PAGE(raw, line))

#define _RAW_RAM_ADDR_PAGE(raw, line) \
		(_RAW_RAM_ADDR(raw, \
		_RAW_RAM_PAGE(raw, line) * raw->entries_in_page))

#define _RAW_RAM_GET(raw, line, data) \
		env_memcpy(data, raw->entry_size, _RAW_RAM_ADDR(raw, (line)), \
		raw->entry_size)

#define _RAW_RAM_SET(raw, line, data) \
		env_memcpy(_RAW_RAM_ADDR(raw, line), raw->entry_size, \
		data, raw->entry_size)



/*
 * RAM Implementation - De-Initialize
 */
static int _raw_ram_deinit(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	OCF_DEBUG_TRACE(cache);

	if (raw->mem_pool) {
		env_vfree(raw->mem_pool);
		raw->mem_pool = NULL;
	}

	return 0;
}

/*
 * RAM Implementation - Initialize
 */
static int _raw_ram_init(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	size_t mem_pool_size;

	OCF_DEBUG_TRACE(cache);

	/* Allocate memory pool for entries */
	mem_pool_size = raw->ssd_pages;
	mem_pool_size *= PAGE_SIZE;
	raw->mem_pool_limit = mem_pool_size;
	raw->mem_pool = env_vzalloc(mem_pool_size);
	if (!raw->mem_pool)
		return -ENOMEM;

	return 0;
}

/*
 * RAM Implementation - Size of
 */
static size_t _raw_ram_size_of(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	size_t size;

	size = raw->ssd_pages;
	size *= PAGE_SIZE;

	return size;
}

/*
 * RAM Implementation - Size on SSD
 */
static uint32_t _raw_ram_size_on_ssd(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	const size_t alignment = 128 * KiB / PAGE_SIZE;

	return DIV_ROUND_UP(raw->ssd_pages, alignment) * alignment;
}

/*
 * RAM Implementation - Checksum
 */
static uint32_t _raw_ram_checksum(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	uint64_t i;
	uint32_t step = 0;
	uint32_t crc = 0;

	for (i = 0; i < raw->ssd_pages; i++) {
		crc = env_crc32(crc, raw->mem_pool + PAGE_SIZE * i, PAGE_SIZE);
		OCF_COND_RESCHED(step, 10000);
	}

	return crc;
}

/*
 * RAM Implementation - Get entry
 */
static int _raw_ram_get(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		void *data, uint32_t size)
{
	ENV_BUG_ON(!_raw_is_valid(raw, line, size));

	return _RAW_RAM_GET(raw, line, data);
}

/*
 * RAM Implementation - Read only entry access
 */
static const void *_raw_ram_rd_access(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		uint32_t size)
{
	ENV_BUG_ON(!_raw_is_valid(raw, line, size));

	return _RAW_RAM_ADDR(raw, line);
}

/*
 * RAM Implementation - Read only entry access
 */
static void *_raw_ram_wr_access(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		uint32_t size)
{
	ENV_BUG_ON(!_raw_is_valid(raw, line, size));

	return _RAW_RAM_ADDR(raw, line);
}

/*
 * RAM Implementation - Set Entry
 */
static int _raw_ram_set(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		void *data, uint32_t size)
{
	ENV_BUG_ON(!_raw_is_valid(raw, line, size));

	return _RAW_RAM_SET(raw, line, data);
}

/*
 * RAM Implementation - Flush specified element from SSD
 */
static int _raw_ram_flush(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line)
{
	OCF_DEBUG_PARAM(cache, "Line = %u", line);
	OCF_DEBUG_PARAM(cache, "Page = %llu", _RAW_RAM_PAGE(raw, line));

	ENV_BUG_ON(!_raw_is_valid(raw, line, raw->entry_size));

	return metadata_io_write(cache, _RAW_RAM_ADDR_PAGE(raw, line),
			_RAW_RAM_PAGE_SSD(raw, line));
}

/*
 * RAM Implementation - Load all IO callback
 */
static int _raw_ram_load_all_io(struct ocf_cache *cache,
		ctx_data_t *data, uint32_t page, void *context)
{
	ocf_cache_line_t line;
	uint32_t raw_page;
	struct ocf_metadata_raw *raw = (struct ocf_metadata_raw *) context;
	uint32_t size = raw->entry_size * raw->entries_in_page;

	ENV_BUG_ON(!_raw_ssd_page_is_valid(raw, page));
	ENV_BUG_ON(size > PAGE_SIZE);

	raw_page = page - raw->ssd_pages_offset;
	line = raw_page * raw->entries_in_page;

	OCF_DEBUG_PARAM(cache, "Line = %u, Page = %u", line, raw_page);

	ctx_data_rd_check(cache->owner, _RAW_RAM_ADDR(raw, line), data, size);
	ctx_data_seek(cache->owner, data, ctx_data_seek_current,
			PAGE_SIZE - size);

	return 0;
}

/*
 * RAM Implementation - Load all metadata elements from SSD
 */
static int _raw_ram_load_all(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	OCF_DEBUG_TRACE(cache);

	return metadata_io_read_i(cache, raw->ssd_pages_offset,
			raw->ssd_pages, _raw_ram_load_all_io, raw);
}

/*
 * RAM Implementation - Flush IO callback - Fill page
 */
static int _raw_ram_flush_all_fill(struct ocf_cache *cache,
		ctx_data_t *data, uint32_t page, void *context)
{
	ocf_cache_line_t line;
	uint32_t raw_page;
	struct ocf_metadata_raw *raw = (struct ocf_metadata_raw *)context;
	uint32_t size = raw->entry_size * raw->entries_in_page;

	ENV_BUG_ON(!_raw_ssd_page_is_valid(raw, page));
	ENV_BUG_ON(size > PAGE_SIZE);

	raw_page = page - raw->ssd_pages_offset;
	line = raw_page * raw->entries_in_page;

	OCF_DEBUG_PARAM(cache, "Line = %u, Page = %u", line, raw_page);

	ctx_data_wr_check(cache->owner, data, _RAW_RAM_ADDR(raw, line), size);
	ctx_data_zero_check(cache->owner, data, PAGE_SIZE - size);

	return 0;
}

/*
 * RAM Implementation - Flush all elements
 */
static int _raw_ram_flush_all(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	OCF_DEBUG_TRACE(cache);

	return metadata_io_write_i(cache, raw->ssd_pages_offset,
			raw->ssd_pages, _raw_ram_flush_all_fill, raw);
}

/*
 * RAM RAM Implementation - Mark to Flush
 */
static void _raw_ram_flush_mark(struct ocf_cache *cache,
		struct ocf_request *rq, uint32_t map_idx, int to_state,
		uint8_t start, uint8_t stop)
{
	if (to_state == DIRTY || to_state == CLEAN) {
		rq->map[map_idx].flush = true;
		rq->info.flush_metadata = true;
	}
}

/*******************************************************************************
 * RAM RAM Implementation - Do Flush Asynchronously
 ******************************************************************************/
struct _raw_ram_flush_ctx {
	struct ocf_metadata_raw *raw;
	struct ocf_request *rq;
	ocf_metadata_asynch_flush_hndl complete;
	env_atomic flush_req_cnt;
	int error;
};

static void _raw_ram_flush_do_asynch_io_complete(struct ocf_cache *cache,
		void *context, int error)
{
	struct _raw_ram_flush_ctx *ctx = context;

	if (error) {
		ctx->error = error;
		ocf_metadata_error(cache);
	}

	if (env_atomic_dec_return(&ctx->flush_req_cnt))
		return;

	OCF_DEBUG_MSG(cache, "Asynchronous flushing complete");

	/* Call metadata flush completed call back */
	ctx->rq->error |= ctx->error;
	ctx->complete(ctx->rq, ctx->error);

	env_free(ctx);
}

/*
 * RAM Implementation - Flush IO callback - Fill page
 */
static int _raw_ram_flush_do_asynch_fill(struct ocf_cache *cache,
		ctx_data_t *data, uint32_t page, void *context)
{
	ocf_cache_line_t line;
	uint32_t raw_page;
	struct _raw_ram_flush_ctx *ctx = context;
	struct ocf_metadata_raw *raw = NULL;
	uint64_t size;

	ENV_BUG_ON(!ctx);

	raw = ctx->raw;
	ENV_BUG_ON(!raw);

	size = raw->entry_size * raw->entries_in_page;
	ENV_BUG_ON(size > PAGE_SIZE);

	raw_page = page - raw->ssd_pages_offset;
	line = raw_page * raw->entries_in_page;

	OCF_DEBUG_PARAM(cache, "Line = %u, Page = %u", line, raw_page);

	ctx_data_wr_check(cache->owner, data, _RAW_RAM_ADDR(raw, line), size);
	ctx_data_zero_check(cache->owner, data, PAGE_SIZE - size);

	return 0;
}

/*
 * RAM RAM Implementation - Do Flush
 */

int _raw_ram_flush_do_page_cmp(const void *item1, const void *item2)
{
	uint32_t *page1 = (uint32_t *)item1;
	uint32_t *page2 = (uint32_t *)item2;

	if (*page1 > *page2)
		return 1;

	if (*page1 < *page2)
		return -1;

	return 0;
}

static void __raw_ram_flush_do_asynch_add_pages(struct ocf_request *rq,
		uint32_t *pages_tab, struct ocf_metadata_raw *raw,
		int *pages_to_flush) {
	int i, j = 0;
	int line_no = rq->core_line_count;
	struct ocf_map_info *map;

	for (i = 0; i < line_no; i++) {
		map = &rq->map[i];
		if (map->flush) {
			pages_tab[j] = _RAW_RAM_PAGE(raw, map->coll_idx);
			j++;
		}
	}

	*pages_to_flush = j;
}

static int _raw_ram_flush_do_asynch(struct ocf_cache *cache,
		struct ocf_request *rq, struct ocf_metadata_raw *raw,
		ocf_end_t complete)
{
	int result = 0, i;
	uint32_t __pages_tab[MAX_STACK_TAB_SIZE];
	uint32_t *pages_tab;
	int line_no = rq->core_line_count;
	int pages_to_flush;
	uint32_t start_page = 0;
	uint32_t count = 0;
	struct _raw_ram_flush_ctx *ctx;

	ENV_BUG_ON(!complete);

	OCF_DEBUG_TRACE(cache);

	if (!rq->info.flush_metadata) {
		/* Nothing to flush call flush callback */
		complete(rq, 0);
		return 0;
	}

	ctx = env_zalloc(sizeof(*ctx), ENV_MEM_NOIO);
	if (!ctx) {
		complete(rq, -ENOMEM);
		return -ENOMEM;
	}

	ctx->rq = rq;
	ctx->complete = complete;
	ctx->raw = raw;
	env_atomic_set(&ctx->flush_req_cnt, 1);

	if (line_no <= MAX_STACK_TAB_SIZE) {
		pages_tab = __pages_tab;
	} else {
		pages_tab = env_zalloc(sizeof(*pages_tab) * line_no, ENV_MEM_NOIO);
		if (!pages_tab) {
			env_free(ctx);
			complete(rq, -ENOMEM);
			return -ENOMEM;
		}
	}

	/* While sorting in progress keep request remaining equal to 1,
	 * to prevent freeing of asynchronous context
	 */

	__raw_ram_flush_do_asynch_add_pages(rq, pages_tab, raw,
			&pages_to_flush);

	env_sort(pages_tab, pages_to_flush, sizeof(*pages_tab),
			_raw_ram_flush_do_page_cmp, NULL);

	i = 0;
	while (i < pages_to_flush) {
		start_page = pages_tab[i];
		count = 1;

		while (true) {
			if ((i + 1) >= pages_to_flush)
				break;

			if (pages_tab[i] == pages_tab[i + 1]) {
				i++;
				continue;
			}

			if ((pages_tab[i] + 1) != pages_tab[i + 1])
				break;

			i++;
			count++;
		}


		env_atomic_inc(&ctx->flush_req_cnt);

		result  |= metadata_io_write_i_asynch(cache, rq->io_queue, ctx,
				raw->ssd_pages_offset + start_page, count,
				_raw_ram_flush_do_asynch_fill,
				_raw_ram_flush_do_asynch_io_complete);

		if (result)
			break;

		i++;
	}

	_raw_ram_flush_do_asynch_io_complete(cache, ctx, result);

	if (line_no > MAX_STACK_TAB_SIZE)
		env_free(pages_tab);

	return result;
}

/*******************************************************************************
 * RAW Interfaces definitions
 ******************************************************************************/
#include "metadata_raw_dynamic.h"
#include "metadata_raw_volatile.h"

static const struct raw_iface IRAW[metadata_raw_type_max] = {
	[metadata_raw_type_ram] = {
		.init			= _raw_ram_init,
		.deinit			= _raw_ram_deinit,
		.size_of		= _raw_ram_size_of,
		.size_on_ssd		= _raw_ram_size_on_ssd,
		.checksum		= _raw_ram_checksum,
		.get			= _raw_ram_get,
		.set			= _raw_ram_set,
		.rd_access		= _raw_ram_rd_access,
		.wr_access		= _raw_ram_wr_access,
		.flush			= _raw_ram_flush,
		.load_all		= _raw_ram_load_all,
		.flush_all		= _raw_ram_flush_all,
		.flush_mark		= _raw_ram_flush_mark,
		.flush_do_asynch	= _raw_ram_flush_do_asynch,
	},
	[metadata_raw_type_dynamic] = {
		.init			= raw_dynamic_init,
		.deinit			= raw_dynamic_deinit,
		.size_of		= raw_dynamic_size_of,
		.size_on_ssd		= raw_dynamic_size_on_ssd,
		.checksum		= raw_dynamic_checksum,
		.get			= raw_dynamic_get,
		.set			= raw_dynamic_set,
		.rd_access		= raw_dynamic_rd_access,
		.wr_access		= raw_dynamic_wr_access,
		.flush			= raw_dynamic_flush,
		.load_all		= raw_dynamic_load_all,
		.flush_all		= raw_dynamic_flush_all,
		.flush_mark		= raw_dynamic_flush_mark,
		.flush_do_asynch	= raw_dynamic_flush_do_asynch,
	},
	[metadata_raw_type_volatile] = {
		.init			= _raw_ram_init,
		.deinit			= _raw_ram_deinit,
		.size_of		= _raw_ram_size_of,
		.size_on_ssd		= raw_volatile_size_on_ssd,
		.checksum		= raw_volatile_checksum,
		.get			= _raw_ram_get,
		.set			= _raw_ram_set,
		.rd_access		= _raw_ram_rd_access,
		.wr_access		= _raw_ram_wr_access,
		.flush			= raw_volatile_flush,
		.load_all		= raw_volatile_load_all,
		.flush_all		= raw_volatile_flush_all,
		.flush_mark		= raw_volatile_flush_mark,
		.flush_do_asynch	= raw_volatile_flush_do_asynch,
	},
	[metadata_raw_type_atomic] = {
		.init			= _raw_ram_init,
		.deinit			= _raw_ram_deinit,
		.size_of		= _raw_ram_size_of,
		.size_on_ssd		= _raw_ram_size_on_ssd,
		.checksum		= _raw_ram_checksum,
		.get			= _raw_ram_get,
		.set			= _raw_ram_set,
		.rd_access		= _raw_ram_rd_access,
		.wr_access		= _raw_ram_wr_access,
		.flush			= _raw_ram_flush,
		.load_all		= _raw_ram_load_all,
		.flush_all		= _raw_ram_flush_all,
		.flush_mark		= raw_atomic_flush_mark,
		.flush_do_asynch	= raw_atomic_flush_do_asynch,
	},
};

/*******************************************************************************
 * RAW Top interface implementation
 ******************************************************************************/

int ocf_metadata_raw_init(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	ENV_BUG_ON(raw->raw_type < metadata_raw_type_min);
	ENV_BUG_ON(raw->raw_type >= metadata_raw_type_max);

	raw->iface = &(IRAW[raw->raw_type]);
	return raw->iface->init(cache, raw);
}

int ocf_metadata_raw_deinit(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	int result;

	if (!raw->iface)
		return 0;

	result = raw->iface->deinit(cache, raw);
	raw->iface = NULL;

	return result;
}

size_t ocf_metadata_raw_size_on_ssd(struct ocf_cache* cache,
                struct ocf_metadata_raw* raw)
{
	ENV_BUG_ON(raw->raw_type < metadata_raw_type_min);
	ENV_BUG_ON(raw->raw_type >= metadata_raw_type_max);

	return IRAW[raw->raw_type].size_on_ssd(cache, raw);
}
