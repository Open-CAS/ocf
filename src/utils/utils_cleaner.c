/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../engine/engine_common.h"
#include "../concurrency/ocf_concurrency.h"
#include "../ocf_request.h"
#include "utils_cleaner.h"
#include "utils_user_part.h"
#include "utils_io.h"
#include "utils_cache_line.h"
#include "../ocf_queue_priv.h"
#include "ocf_env_refcnt.h"

#define OCF_UTILS_CLEANER_DEBUG 0

#if 1 == OCF_UTILS_CLEANER_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Utils][cleaner] %s\n", __func__)

#define OCF_DEBUG_MSG(cache, msg) \
	ocf_cache_log(cache, log_info, "[Utils][cleaner] %s - %s\n", \
			__func__, msg)

#define OCF_DEBUG_PARAM(cache, format, ...) \
	ocf_cache_log(cache, log_info, "[Utils][cleaner] %s - "format"\n", \
			__func__, ##__VA_ARGS__)
#else
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_MSG(cache, msg)
#define OCF_DEBUG_PARAM(cache, format, ...)
#endif

/*
 * Allocate cleaning request
 */
static struct ocf_request *_ocf_cleaner_alloc_req(struct ocf_cache *cache,
		uint32_t count, const struct ocf_cleaner_attribs *attribs)
{
	struct ocf_request *req;
	int ret;

	req = ocf_req_new_cleaner(cache, attribs->io_queue, count);
	if (!req)
		return NULL;

	req->info.internal = true;
	req->info.cleaner_cache_line_lock = attribs->lock_cacheline;

	/* Allocate pages for cleaning IO */
	req->data = ctx_data_alloc(cache->owner,
			OCF_DIV_ROUND_UP((uint64_t)count * ocf_line_size(cache), PAGE_SIZE));
	if (!req->data) {
		ocf_req_put(req);
		return NULL;
	}

	ret = ctx_data_mlock(cache->owner, req->data);
	if (ret) {
		ctx_data_free(cache->owner, req->data);
		ocf_req_put(req);
		return NULL;
	}

	return req;
}

enum {
	ocf_cleaner_req_type_master = 1,
	ocf_cleaner_req_type_slave = 2
};

static inline uint32_t _ocf_cleaner_get_req_max_count(uint32_t count,
		bool low_mem)
{
	if (low_mem || count <= 4096)
		return count < 128 ? count : 128;

	return 1024;
}

static struct ocf_request *_ocf_cleaner_alloc_master_req(
		struct ocf_cache *cache, uint32_t count,
		const struct ocf_cleaner_attribs *attribs)
{
	struct ocf_request *req;

	req =_ocf_cleaner_alloc_req(cache, count, attribs);
	if (unlikely(!req)) {
		/* Some memory allocation error, try re-allocate request */
		count = _ocf_cleaner_get_req_max_count(count, true);
		req = _ocf_cleaner_alloc_req(cache, count, attribs);
	}

	if (unlikely(!req))
		return NULL;

	/* Set type of cleaning request */
	req->master_io_req_type = ocf_cleaner_req_type_master;

	/* In master, save completion context and function */
	req->priv = attribs->cmpl_context;
	req->master_io_req = attribs->cmpl_fn;
	req->complete_queue = attribs->cmpl_queue;

	/* The count of all requests */
	env_atomic_set(&req->master_remaining, 1);

	/* Keep master alive till all sub-requests complete */
	ocf_req_get(req);

	OCF_DEBUG_PARAM(cache, "New master request, count = %u", count);

	return req;
}

static struct ocf_request *_ocf_cleaner_alloc_slave_req(
		struct ocf_request *master, uint32_t count,
		const struct ocf_cleaner_attribs *attribs)
{
	struct ocf_request *req;

	req = _ocf_cleaner_alloc_req(master->cache, count, attribs);
	if (unlikely(!req)) {
		/* Some memory allocation error, try re-allocate request */
		count = _ocf_cleaner_get_req_max_count(count, true);
		req = _ocf_cleaner_alloc_req(master->cache, count, attribs);
	}

	if (unlikely(!req))
		return NULL;

	/* Set type of cleaning request */
	req->master_io_req_type = ocf_cleaner_req_type_slave;

	/* Slave request contains reference to master */
	req->master_io_req = master;

	OCF_DEBUG_PARAM(req->cache,
			"New slave request, count = %u,all requests count = %d",
			count, env_atomic_read(&master->master_remaining));

	return req;
}

static void _ocf_cleaner_dealloc_req(struct ocf_request *req)
{
	ctx_data_secure_erase(req->cache->owner, req->data);
	ctx_data_munlock(req->cache->owner, req->data);
	ctx_data_free(req->cache->owner, req->data);
	ocf_req_put(req);
}

/*
 * cleaner - Get clean result
 */
static void _ocf_cleaner_set_error(struct ocf_request *req)
{
	struct ocf_request *master = NULL;

	if (ocf_cleaner_req_type_master == req->master_io_req_type) {
		master = req;
	} else if (ocf_cleaner_req_type_slave == req->master_io_req_type) {
		master = req->master_io_req;
	} else {
		ENV_BUG();
		return;
	}

	master->error = -OCF_ERR_IO;
}

static int _ocf_cleaner_complete(struct ocf_request *master)
{
	ocf_req_end_t cmpl;

	cmpl = master->master_io_req;
	cmpl(master->priv, master->error);
	ocf_req_put(master);

	return 0;
}

static void _ocf_cleaner_complete_req(struct ocf_request *req)
{
	struct ocf_request *master = NULL;

	if (ocf_cleaner_req_type_master == req->master_io_req_type) {
		OCF_DEBUG_MSG(req->cache, "Master completion");
		master = req;
	} else if (ocf_cleaner_req_type_slave == req->master_io_req_type) {
		OCF_DEBUG_MSG(req->cache, "Slave completion");
		master = req->master_io_req;
	} else {
		ENV_BUG();
		return;
	}

	OCF_DEBUG_PARAM(req->cache, "Master requests remaining = %d",
			env_atomic_read(&master->master_remaining));

	if (env_atomic_dec_return(&master->master_remaining)) {
		/* Not all requests completed */
		return;
	}

	OCF_DEBUG_MSG(req->cache, "All cleaning request completed");

	if (master->complete_queue) {
		ocf_queue_push_req_cb(master, _ocf_cleaner_complete,
				OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
	} else {
		_ocf_cleaner_complete(master);
	}
}

static void _ocf_cleaner_on_resume(struct ocf_request *req)
{
	OCF_DEBUG_TRACE(req->cache);
	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

/*
 * cleaner - Cache line lock, function lock cache lines depends on attributes
 */
static int _ocf_cleaner_cache_line_lock(struct ocf_request *req)
{
	if (!req->info.cleaner_cache_line_lock)
		return OCF_LOCK_ACQUIRED;

	OCF_DEBUG_TRACE(req->cache);

	return ocf_req_async_lock_rd(ocf_cache_line_concurrency(req->cache),
			req, _ocf_cleaner_on_resume);
}

/*
 * cleaner - Cache line unlock, function unlock cache lines
 * depends on attributes
 */
static void _ocf_cleaner_cache_line_unlock(struct ocf_request *req)
{
	if (req->info.cleaner_cache_line_lock) {
		OCF_DEBUG_TRACE(req->cache);
		ocf_req_unlock(req->cache->device->concurrency.cache_line,
				req);
	}
}

static bool _ocf_cleaner_sector_is_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t sector)
{
	bool dirty = metadata_test_dirty_one(cache, line, sector);
	bool valid = metadata_test_valid_one(cache, line, sector);

	if (!valid && dirty) {
		/* not valid but dirty - IMPROPER STATE!!! */
		ENV_BUG();
	}

	return valid ? dirty : false;
}

static void _ocf_cleaner_finish_req(struct ocf_request *req)
{
	/* Handle cache lines unlocks */
	_ocf_cleaner_cache_line_unlock(req);

	/* Signal completion to the caller of cleaning */
	_ocf_cleaner_complete_req(req);

	/* Free allocated resources */
	_ocf_cleaner_dealloc_req(req);
}

static void _ocf_cleaner_flush_cache_end(struct ocf_request *req, int error)
{
	if (error)
		ocf_metadata_error(req->cache);

	OCF_DEBUG_MSG(req->cache, "Cache flush finished");

	_ocf_cleaner_finish_req(req);
}

static int _ocf_cleaner_fire_flush_cache(struct ocf_request *req)
{
	OCF_DEBUG_TRACE(req->cache);

	ocf_req_forward_cache_init(req, _ocf_cleaner_flush_cache_end);
	ocf_req_forward_cache_flush(req);

	return 0;
}

static void _ocf_cleaner_metadata_io_end(struct ocf_request *req, int error)
{
	if (error) {
		ocf_metadata_error(req->cache);
		req->error = error;
		_ocf_cleaner_finish_req(req);
		return;
	}

	OCF_DEBUG_MSG(req->cache, "Metadata flush finished");

	req->engine_handler = _ocf_cleaner_fire_flush_cache;
	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

static int _ocf_cleaner_update_metadata(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;
	const struct ocf_map_info *iter = req->map;
	uint32_t i;
	ocf_cache_line_t cache_line;
	ocf_core_id_t core_id;

	OCF_DEBUG_TRACE(req->cache);

	/* Update metadata */
	for (i = 0; i < req->core_line_count; i++, iter++) {
		if (!iter->flush)
			continue;

		if (iter->invalid) {
			/* An error, do not clean */
			continue;
		}

		cache_line = iter->coll_idx;

		ocf_hb_cline_prot_lock_wr(&cache->metadata.lock,
				req->lock_idx, req->map[i].core_id,
				req->map[i].core_line);

		if (metadata_test_dirty(cache, cache_line)) {
			ocf_metadata_get_core_and_part_id(cache, cache_line,
					&core_id, &req->part_id);

			ocf_metadata_start_collision_shared_access(cache,
					cache_line);
			set_cache_line_clean(cache, 0,
					ocf_line_end_sector(cache), req, i);
			ocf_metadata_end_collision_shared_access(cache,
					cache_line);
		}

		ocf_hb_cline_prot_unlock_wr(&cache->metadata.lock,
				req->lock_idx, req->map[i].core_id,
				req->map[i].core_line);
	}

	if (!req->cache->metadata.is_volatile) {
		ocf_metadata_flush_do_asynch(cache, req, _ocf_cleaner_metadata_io_end);
	} else {
		_ocf_cleaner_finish_req(req);
	}
	return 0;
}

static void _ocf_cleaner_flush_core_end(struct ocf_request *req, int error)
{
	struct ocf_map_info *iter = req->map;
	uint32_t i;

	OCF_DEBUG_MSG(req->cache, "Core flush finished");

	if (error) {
		/* Flush error, set error for all cleaned cache lines */
		for (i = 0; i < req->core_line_count; i++, iter++) {
			if (!iter->flush)
				continue;

			iter->invalid = true;
		}

		_ocf_cleaner_set_error(req);
	}

	/*
	 * All core writes done, switch to post cleaning activities
	 */
	req->engine_handler = _ocf_cleaner_update_metadata;
	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

static int _ocf_cleaner_fire_flush_core(struct ocf_request *req)
{
	/* Submit flush request */
	ocf_req_forward_core_init(req, _ocf_cleaner_flush_core_end);
	ocf_req_forward_core_flush(req);

	return 0;
}

static void _ocf_cleaner_core_io_end(struct ocf_request *req, int error)
{
	struct ocf_map_info *iter = req->map;
	uint32_t i;

	OCF_DEBUG_MSG(req->cache, "Core writes finished");

	if (error) {
		for (i = 0; i < req->core_line_count; i++, iter++) {
			if (!iter->flush)
				continue;

			iter->invalid = true;

			ocf_core_stats_core_error_update(req->core, OCF_WRITE);
		}

		_ocf_cleaner_set_error(req);
	}

	req->engine_handler = _ocf_cleaner_fire_flush_core;
	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

static void _ocf_cleaner_core_io_for_dirty_range(struct ocf_request *req,
		struct ocf_map_info *iter, uint64_t begin, uint64_t end)
{
	uint64_t addr, offset;
	ocf_cache_t cache = req->cache;
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache,
			iter->coll_idx);

	addr = (ocf_line_size(cache) * iter->core_line)
			+ SECTORS_TO_BYTES(begin);
	offset = (ocf_line_size(cache) * iter->hash)
			+ SECTORS_TO_BYTES(begin);

	ocf_core_stats_core_block_update(req->core, part_id, OCF_WRITE,
			SECTORS_TO_BYTES(end - begin));

	OCF_DEBUG_PARAM(req->cache, "Core write, line = %llu, "
			"sector = %llu, count = %llu", iter->core_line, begin,
			end - begin);

	ocf_req_forward_core_io(req, OCF_WRITE, addr,
			SECTORS_TO_BYTES(end - begin), offset);
}

static void _ocf_cleaner_core_submit_io(struct ocf_request *req,
		struct ocf_map_info *iter)
{
	uint64_t i, dirty_start = 0;
	struct ocf_cache *cache = req->cache;
	bool counting_dirty = false;

	/* Check integrity of entry to be cleaned */
	if (metadata_test_valid(cache, iter->coll_idx)
		&& metadata_test_dirty(cache, iter->coll_idx)) {

		_ocf_cleaner_core_io_for_dirty_range(req, iter, 0,
				ocf_line_sectors(cache));

		return;
	}

	/* Sector cleaning, a little effort is required to this */
	for (i = 0; i < ocf_line_sectors(cache); i++) {
		if (!_ocf_cleaner_sector_is_dirty(cache, iter->coll_idx, i)) {
			if (counting_dirty) {
				counting_dirty = false;
				_ocf_cleaner_core_io_for_dirty_range(req, iter,
						dirty_start, i);
			}

			continue;
		}

		if (!counting_dirty) {
			counting_dirty = true;
			dirty_start = i;
		}

	}

	if (counting_dirty)
		_ocf_cleaner_core_io_for_dirty_range(req, iter, dirty_start, i);
}

static int _ocf_cleaner_fire_core(struct ocf_request *req)
{
	uint32_t i;
	struct ocf_map_info *iter;
	ocf_cache_t cache = req->cache;

	OCF_DEBUG_TRACE(req->cache);

	ocf_req_forward_core_init(req, _ocf_cleaner_core_io_end);

	/* Submits writes to the core */
	ocf_req_forward_core_get(req);
	for (i = 0; i < req->core_line_count; i++) {
		iter = &(req->map[i]);

		if (iter->invalid) {
			/* IO read error on cache, skip this item */
			continue;
		}

		if (!iter->flush)
			continue;

		ocf_hb_cline_prot_lock_rd(&cache->metadata.lock,
				req->lock_idx, req->map[i].core_id,
				req->map[i].core_line);

		_ocf_cleaner_core_submit_io(req, iter);

		ocf_hb_cline_prot_unlock_rd(&cache->metadata.lock,
				req->lock_idx, req->map[i].core_id,
				req->map[i].core_line);
	}
	ocf_req_forward_core_put(req);

	return 0;
}

static void _ocf_cleaner_cache_io_end(struct ocf_request *req, int error)
{
	struct ocf_map_info *iter = req->map;
	uint32_t i;

	OCF_DEBUG_MSG(req->cache, "Cache reads finished");

	if (error) {
		for (i = 0; i < req->core_line_count; i++, iter++) {
			if (!iter->flush)
				continue;

			iter->invalid = true;

			ocf_core_stats_cache_error_update(req->core, OCF_READ);
		}
		_ocf_cleaner_set_error(req);
	}

	req->engine_handler = _ocf_cleaner_fire_core;
	ocf_queue_push_req(req, OCF_QUEUE_ALLOW_SYNC | OCF_QUEUE_PRIO_HIGH);
}

/*
 * cleaner - Traverse cache lines to be cleaned, detect sequential IO, and
 * perform cache reads and core writes
 */
static int _ocf_cleaner_fire_cache(struct ocf_request *req)
{
	ocf_cache_t cache = req->cache;
	uint32_t i;
	struct ocf_map_info *iter = req->map;
	uint64_t addr, offset;
	ocf_part_id_t part_id;

	ocf_req_forward_cache_init(req, _ocf_cleaner_cache_io_end);
	req->bytes = ocf_line_size(cache);

	ocf_req_forward_cache_get(req);
	for (i = 0; i < req->core_line_count; i++, iter++) {
		if (!iter->flush)
			continue;

		OCF_DEBUG_PARAM(req->cache, "Cache read, line =  %u",
				iter->coll_idx);

		addr = iter->coll_idx;
		addr *= ocf_line_size(cache);
		addr += cache->device->metadata_offset;

		offset = ocf_line_size(cache) * iter->hash;

		part_id = ocf_metadata_get_partition_id(cache, iter->coll_idx);

		ocf_core_stats_cache_block_update(req->core, part_id, OCF_READ,
				ocf_line_size(cache));

		req->addr = iter->core_line * ocf_line_size(cache);

		ocf_req_forward_cache_io(req, OCF_READ, addr,
				ocf_line_size(cache), offset);
	}
	ocf_req_forward_cache_put(req);

	return 0;
}

static int _ocf_cleaner_check_map(struct ocf_request *req)
{
	ocf_core_id_t core_id;
	uint64_t core_line;
	int i;

	for (i = 0; i < req->core_line_count; ++i) {
		ocf_metadata_get_core_info(req->cache, req->map[i].coll_idx,
				&core_id, &core_line);

		if (core_id != req->map[i].core_id)
			continue;

		if (core_line != req->map[i].core_line)
			continue;

		if (!metadata_test_dirty(req->cache, req->map[i].coll_idx))
			continue;

		req->map[i].flush = true;
	}

	_ocf_cleaner_fire_cache(req);

	return 0;
}

static int _ocf_cleaner_do_fire(struct ocf_request *req)
{
	struct ocf_request *master;
	int result;

	req->engine_handler = _ocf_cleaner_check_map;
	req->addr = req->core_line_count * ocf_line_size(req->cache);

	master = (req->master_io_req_type == ocf_cleaner_req_type_master) ?
			req : req->master_io_req;

	/* Handle cache lines locks */
	result = _ocf_cleaner_cache_line_lock(req);

	if (result >= 0) {
		env_atomic_inc(&master->master_remaining);

		if (result == OCF_LOCK_ACQUIRED) {
			OCF_DEBUG_MSG(req->cache, "Lock acquired");
			_ocf_cleaner_check_map(req);
		} else {
			OCF_DEBUG_MSG(req->cache, "NO Lock");
		}
		return  0;
	} else {
		OCF_DEBUG_MSG(req->cache, "Lock error");
	}

	return result;
}

static void _ocf_cleaner_fire_error(struct ocf_request *master,
		struct ocf_request *req, int err)
{
	master->error = err;
	_ocf_cleaner_dealloc_req(req);
}

static uint32_t ocf_cleaner_populate_req(struct ocf_request *req, uint32_t curr,
		const struct ocf_cleaner_attribs *attribs)
{
	uint32_t count = attribs->count;
	uint32_t map_max = req->core_line_count, map_curr;
	ocf_cache_line_t cache_line;
	uint64_t core_sector;
	ocf_core_id_t core_id, last_core_id = OCF_CORE_ID_INVALID;

	for (map_curr = 0; map_curr < map_max && curr < count; curr++) {
		if (attribs->getter(req->cache, attribs->getter_context,
					curr, &cache_line)) {
			continue;
		}

		/* Get mapping info */
		ocf_metadata_get_core_info(req->cache, cache_line,
				&core_id, &core_sector);

		if (last_core_id == OCF_CORE_ID_INVALID) {
			last_core_id = core_id;
			req->core = ocf_cache_get_core(req->cache, core_id);
		}

		if (core_id != last_core_id)
			break;

		req->map[map_curr].core_id = core_id;
		req->map[map_curr].core_line = core_sector;
		req->map[map_curr].coll_idx = cache_line;
		req->map[map_curr].status = LOOKUP_HIT;
		req->map[map_curr].hash = map_curr;
		map_curr++;
	}

	req->core_line_count = map_curr;

	return curr;
}

/*
 * cleaner - Main function
 */
void ocf_cleaner_fire(struct ocf_cache *cache,
		const struct ocf_cleaner_attribs *attribs)
{
	uint32_t count = attribs->count, curr = 0;
	/* max cache lines to be cleaned with one request: 1024 if over 4k lines
	 * to be flushed, otherwise 128. for large cleaning operations, 1024 is
	 * optimal number, but for smaller 1024 is too large to benefit from
	 * cleaning request overlapping
	 */
	uint32_t max = _ocf_cleaner_get_req_max_count(count, false);
	/* it is possible that more than one cleaning request will be generated
	 * for each cleaning order, thus multiple allocations. At the end of
	 * loop, req is set to zero and NOT deallocated, as deallocation is
	 * handled in completion.
	 * In addition first request we call master which contains completion
	 * contexts. Then succeeding request we call salve requests which
	 * contains reference to the master request
	 */
	struct ocf_request *req = NULL, *master;
	int err;

	/* Allocate master request */
	master = _ocf_cleaner_alloc_master_req(cache, max, attribs);
	if (unlikely(!master)) {
		attribs->cmpl_fn(attribs->cmpl_context, -OCF_ERR_NO_MEM);
		return;
	}

	curr = ocf_cleaner_populate_req(master, curr, attribs);

	if (unlikely(master->core_line_count == 0)) {
		_ocf_cleaner_dealloc_req(master);
		goto out;
	}

	err = _ocf_cleaner_do_fire(master);
	if (err) {
		_ocf_cleaner_fire_error(master, master, err);
		goto out;
	}

	while (curr < count) {
		max = OCF_MIN(max, count - curr);
		req = _ocf_cleaner_alloc_slave_req(master, max, attribs);
		if (!req) {
			master->error = -OCF_ERR_NO_MEM;
			break;
		}
		curr = ocf_cleaner_populate_req(req, curr, attribs);
		if (unlikely(req->core_line_count == 0)) {
			_ocf_cleaner_dealloc_req(req);
			break;
		}

		err = _ocf_cleaner_do_fire(req);
		if (err) {
			_ocf_cleaner_fire_error(master, req, err);
			break;
		}
	}

out:
	_ocf_cleaner_complete_req(master);
}

static int _ocf_cleaner_do_flush_data_getter(struct ocf_cache *cache,
		void *context, uint32_t item, ocf_cache_line_t *line)
{
	struct flush_data *flush = context;

	if (flush[item].cache_line < cache->device->collision_table_entries) {
		(*line) = flush[item].cache_line;
		return 0;
	} else {
		return -1;
	}
}

int ocf_cleaner_do_flush_data_async(struct ocf_cache *cache,
		struct flush_data *flush, uint32_t count,
		struct ocf_cleaner_attribs *attribs)
{
	attribs->getter = _ocf_cleaner_do_flush_data_getter;
	attribs->getter_context = flush;
	attribs->count = count;

	ocf_cleaner_fire(cache, attribs);

	return 0;
}

/* Helper function for 'sort' */
static int _ocf_cleaner_cmp(const void *a, const void *b)
{
	struct flush_data *_a = (struct flush_data *)a;
	struct flush_data *_b = (struct flush_data *)b;

	/* TODO: FIXME get rid of static */
	static uint32_t step = 0;

	OCF_COND_RESCHED(step, 1000000)

	if (_a->core_id == _b->core_id)
		return (_a->core_line > _b->core_line) ? 1 : -1;

	return (_a->core_id > _b->core_id) ? 1 : -1;
}

static void _ocf_cleaner_swap(void *a, void *b, int size)
{
	struct flush_data *_a = (struct flush_data *)a;
	struct flush_data *_b = (struct flush_data *)b;
	struct flush_data t;

	t = *_a;
	*_a = *_b;
	*_b = t;
}

void ocf_cleaner_sort_flush_data(struct flush_data *flush_data, uint32_t count)
{
	env_sort(flush_data, count, sizeof(*flush_data),
			_ocf_cleaner_cmp, _ocf_cleaner_swap);
}

void ocf_cleaner_sort_flush_containers(struct flush_container *fctbl,
		uint32_t num)
{
	int i;

	for (i = 0; i < num; i++) {
		ocf_cleaner_sort_flush_data(fctbl[i].flush_data,
				fctbl[i].count);
	}
}

void ocf_cleaner_refcnt_freeze(ocf_cache_t cache)
{
	struct ocf_user_part *curr_part;
	ocf_part_id_t part_id;

	for_each_user_part(cache, curr_part, part_id)
		env_refcnt_freeze(&curr_part->cleaning.counter);
}

void ocf_cleaner_refcnt_unfreeze(ocf_cache_t cache)
{
	struct ocf_user_part *curr_part;
	ocf_part_id_t part_id;

	for_each_user_part(cache, curr_part, part_id)
		env_refcnt_unfreeze(&curr_part->cleaning.counter);
}

static void ocf_cleaner_refcnt_register_zero_cb_finish(void *priv)
{
	struct ocf_cleaner_wait_context *ctx = priv;

	if (!env_atomic_dec_return(&ctx->waiting))
		ctx->cb(ctx->priv);
}

void ocf_cleaner_refcnt_register_zero_cb(ocf_cache_t cache,
		struct ocf_cleaner_wait_context *ctx,
		ocf_cleaner_refcnt_zero_cb_t cb, void *priv)
{
	struct ocf_user_part *curr_part;
	ocf_part_id_t part_id;

	env_atomic_set(&ctx->waiting, 1);
	ctx->cb = cb;
	ctx->priv = priv;

	for_each_user_part(cache, curr_part, part_id) {
		env_atomic_inc(&ctx->waiting);
		env_refcnt_register_zero_cb(&curr_part->cleaning.counter,
				ocf_cleaner_refcnt_register_zero_cb_finish, ctx);
	}

	ocf_cleaner_refcnt_register_zero_cb_finish(ctx);
}
