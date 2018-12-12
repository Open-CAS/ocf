/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../engine/engine_common.h"
#include "../concurrency/ocf_concurrency.h"
#include "utils_cleaner.h"
#include "utils_rq.h"
#include "utils_io.h"
#include "utils_cache_line.h"

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


struct ocf_cleaner_sync {
	env_completion cmpl;
	int error;
};

/*
 * Allocate cleaning request
 */
static struct ocf_request *_ocf_cleaner_alloc_rq(struct ocf_cache *cache,
		uint32_t count, const struct ocf_cleaner_attribs *attribs)
{
	struct ocf_request *rq = ocf_rq_new_extended(cache, 0, 0,
			count * ocf_line_size(cache), OCF_READ);
	int ret;

	if (!rq)
		return NULL;

	rq->info.internal = true;
	rq->info.cleaner_cache_line_lock = attribs->cache_line_lock;

	/* Allocate pages for cleaning IO */
	rq->data = ctx_data_alloc(cache->owner,
			ocf_line_size(cache) / PAGE_SIZE * count);
	if (!rq->data) {
		ocf_rq_put(rq);
		return NULL;
	}

	ret = ctx_data_mlock(cache->owner, rq->data);
	if (ret) {
		ctx_data_free(cache->owner, rq->data);
		ocf_rq_put(rq);
		return NULL;
	}

	rq->io_queue = attribs->io_queue;

	return rq;
}

enum {
	ocf_cleaner_rq_type_master = 1,
	ocf_cleaner_rq_type_slave = 2
};

static struct ocf_request *_ocf_cleaner_alloc_master_rq(
	struct ocf_cache *cache, uint32_t count,
	const struct ocf_cleaner_attribs *attribs)
{
	struct ocf_request *rq = _ocf_cleaner_alloc_rq(cache, count, attribs);

	if (rq) {
		/* Set type of cleaning request */
		rq->master_io_req_type = ocf_cleaner_rq_type_master;

		/* In master, save completion context and function */
		rq->priv = attribs->cmpl_context;
		rq->master_io_req = attribs->cmpl_fn;

		/* The count of all requests */
		env_atomic_set(&rq->master_remaining, 1);

		OCF_DEBUG_PARAM(cache, "New master request, count = %u",
				count);
	}
	return rq;
}

static struct ocf_request *_ocf_cleaner_alloc_slave_rq(
		struct ocf_request *master,
		uint32_t count, const struct ocf_cleaner_attribs *attribs)
{
	struct ocf_request *rq = _ocf_cleaner_alloc_rq(
			master->cache, count, attribs);

	if (rq) {
		/* Set type of cleaning request */
		rq->master_io_req_type = ocf_cleaner_rq_type_slave;

		/* Slave refers to master request, get its reference counter */
		ocf_rq_get(master);

		/* Slave request contains reference to master */
		rq->master_io_req = master;

		/* One more additional slave request, increase global counter
		 * of requests count
		 */
		env_atomic_inc(&master->master_remaining);

		OCF_DEBUG_PARAM(rq->cache,
			"New slave request, count = %u,all requests count = %d",
			count, env_atomic_read(&master->master_remaining));
	}
	return rq;
}

static void _ocf_cleaner_dealloc_rq(struct ocf_request *rq)
{
	if (ocf_cleaner_rq_type_slave == rq->master_io_req_type) {
		/* Slave contains reference to the master request,
		 * release reference counter
		 */
		struct ocf_request *master = rq->master_io_req;

		OCF_DEBUG_MSG(rq->cache, "Put master request by slave");
		ocf_rq_put(master);

		OCF_DEBUG_MSG(rq->cache, "Free slave request");
	} else if (ocf_cleaner_rq_type_master == rq->master_io_req_type) {
		OCF_DEBUG_MSG(rq->cache, "Free master request");
	} else {
		ENV_BUG();
	}

	ctx_data_secure_erase(rq->cache->owner, rq->data);
	ctx_data_munlock(rq->cache->owner, rq->data);
	ctx_data_free(rq->cache->owner, rq->data);
	ocf_rq_put(rq);
}

/*
 * cleaner - Get clean result
 */
static void _ocf_cleaner_set_error(struct ocf_request *rq)
{
	struct ocf_request *master = NULL;

	if (ocf_cleaner_rq_type_master == rq->master_io_req_type) {
		master = rq;
	} else if (ocf_cleaner_rq_type_slave == rq->master_io_req_type) {
		master = rq->master_io_req;
	} else {
		ENV_BUG();
		return;
	}

	master->error = -EIO;
}

static void _ocf_cleaner_complete_rq(struct ocf_request *rq)
{
	struct ocf_request *master = NULL;
	ocf_req_end_t cmpl;

	if (ocf_cleaner_rq_type_master == rq->master_io_req_type) {
		OCF_DEBUG_MSG(rq->cache, "Master completion");
		master = rq;
	} else if (ocf_cleaner_rq_type_slave == rq->master_io_req_type) {
		OCF_DEBUG_MSG(rq->cache, "Slave completion");
		master = rq->master_io_req;
	} else {
		ENV_BUG();
		return;
	}

	OCF_DEBUG_PARAM(rq->cache, "Master requests remaining = %d",
			env_atomic_read(&master->master_remaining));

	if (env_atomic_dec_return(&master->master_remaining)) {
		/* Not all requests completed */
		return;
	}

	OCF_DEBUG_MSG(rq->cache, "All cleaning request completed");

	/* Only master contains completion function and completion context */
	cmpl = master->master_io_req;
	cmpl(master->priv, master->error);
}

/*
 * cleaner - Cache line lock, function lock cache lines depends on attributes
 */
static int _ocf_cleaner_cache_line_lock(struct ocf_request *rq)
{
	if (!rq->info.cleaner_cache_line_lock)
		return OCF_LOCK_ACQUIRED;

	OCF_DEBUG_TRACE(rq->cache);

	return ocf_rq_trylock_rd(rq);
}

/*
 * cleaner - Cache line unlock, function unlock cache lines
 * depends on attributes
 */
static void _ocf_cleaner_cache_line_unlock(struct ocf_request *rq)
{
	if (rq->info.cleaner_cache_line_lock) {
		OCF_DEBUG_TRACE(rq->cache);
		ocf_rq_unlock(rq);
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

static void _ocf_cleaner_finish_rq(struct ocf_request *rq)
{
	/* Handle cache lines unlocks */
	_ocf_cleaner_cache_line_unlock(rq);

	/* Signal completion to the caller of cleaning */
	_ocf_cleaner_complete_rq(rq);

	/* Free allocated resources */
	_ocf_cleaner_dealloc_rq(rq);
}

static void _ocf_cleaner_flush_cache_io_end(struct ocf_io *io, int error)
{
	struct ocf_request *rq = io->priv1;

	if (error) {
		ocf_metadata_error(rq->cache);
		rq->error = error;
	}

	OCF_DEBUG_MSG(rq->cache, "Cache flush finished");

	_ocf_cleaner_finish_rq(rq);
}

static int _ocf_cleaner_fire_flush_cache(struct ocf_request *rq)
{
	struct ocf_io *io;

	OCF_DEBUG_TRACE(rq->cache);

	io = ocf_dobj_new_io(&rq->cache->device->obj);
	if (!io) {
		ocf_metadata_error(rq->cache);
		rq->error = -ENOMEM;
		return -ENOMEM;
	}

	ocf_io_configure(io, 0, 0, OCF_WRITE, 0, 0); 
	ocf_io_set_cmpl(io, rq, NULL, _ocf_cleaner_flush_cache_io_end);

	ocf_dobj_submit_flush(io);

	return 0;
}

static const struct ocf_io_if _io_if_flush_cache = {
	.read = _ocf_cleaner_fire_flush_cache,
	.write = _ocf_cleaner_fire_flush_cache,
};

static void _ocf_cleaner_metadata_io_end(struct ocf_request *rq, int error)
{
	if (error) {
		ocf_metadata_error(rq->cache);
		rq->error = error;
		_ocf_cleaner_finish_rq(rq);
		return;
	}

	OCF_DEBUG_MSG(rq->cache, "Metadata flush finished");

	rq->io_if = &_io_if_flush_cache;
	ocf_engine_push_rq_front(rq, true);
}

static int _ocf_cleaner_update_metadata(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;
	const struct ocf_map_info *iter = rq->map;
	uint32_t i;
	ocf_cache_line_t cache_line;

	OCF_DEBUG_TRACE(rq->cache);

	OCF_METADATA_LOCK_WR();
	/* Update metadata */
	for (i = 0; i < rq->core_line_count; i++, iter++) {
		if (iter->status == LOOKUP_MISS)
			continue;

		if (iter->invalid) {
			/* An error, do not clean */
			continue;
		}

		cache_line = iter->coll_idx;

		if (!metadata_test_dirty(cache, cache_line))
			continue;

		ocf_metadata_get_core_and_part_id(cache, cache_line,
				&rq->core_id, &rq->part_id);

		set_cache_line_clean(cache, 0, ocf_line_end_sector(cache), rq,
				i);
	}

	ocf_metadata_flush_do_asynch(cache, rq, _ocf_cleaner_metadata_io_end);
	OCF_METADATA_UNLOCK_WR();

	return 0;
}

static const struct ocf_io_if _io_if_update_metadata = {
		.read = _ocf_cleaner_update_metadata,
		.write = _ocf_cleaner_update_metadata,
};

static void _ocf_cleaner_flush_cores_io_end(struct ocf_map_info *map,
		struct ocf_request *rq, int error)
{
	uint32_t i;
	struct ocf_map_info *iter = rq->map;

	if (error) {
		/* Flush error, set error for all cache line of this core */
		for (i = 0; i < rq->core_line_count; i++, iter++) {
			if (iter->status == LOOKUP_MISS)
				continue;

			if (iter->core_id == map->core_id)
				iter->invalid = true;
		}

		_ocf_cleaner_set_error(rq);
	}

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	OCF_DEBUG_MSG(rq->cache, "Core flush finished");

	/*
	 * All core writes done, switch to post cleaning activities
	 */
	rq->io_if = &_io_if_update_metadata;
	ocf_engine_push_rq_front(rq, true);
}

static void _ocf_cleaner_flush_cores_io_cmpl(struct ocf_io *io, int error)
{
	_ocf_cleaner_flush_cores_io_end(io->priv1, io->priv2, error);

	ocf_io_put(io);
}

static int _ocf_cleaner_fire_flush_cores(struct ocf_request *rq)
{
	uint32_t i;
	ocf_core_id_t core_id = OCF_CORE_MAX;
	struct ocf_cache *cache = rq->cache;
	struct ocf_map_info *iter = rq->map;
	struct ocf_io *io;

	OCF_DEBUG_TRACE(rq->cache);

	/* Protect IO completion race */
	env_atomic_set(&rq->req_remaining, 1);

	/* Submit flush requests */
	for (i = 0; i < rq->core_line_count; i++, iter++) {
		if (iter->invalid) {
			/* IO error, skip this item */
			continue;
		}

		if (iter->status == LOOKUP_MISS)
			continue;

		if (core_id == iter->core_id)
			continue;

		core_id = iter->core_id;

		env_atomic_inc(&rq->req_remaining);

		io = ocf_new_core_io(cache, core_id);
		if (!io) {
			_ocf_cleaner_flush_cores_io_end(iter, rq, -ENOMEM);
			continue;
		}

		ocf_io_configure(io, 0, 0, OCF_WRITE, 0, 0);
		ocf_io_set_cmpl(io, iter, rq, _ocf_cleaner_flush_cores_io_cmpl);

		ocf_dobj_submit_flush(io);
	}

	/* Protect IO completion race */
	_ocf_cleaner_flush_cores_io_end(NULL, rq, 0);

	return 0;
}

static const struct ocf_io_if _io_if_flush_cores = {
	.read = _ocf_cleaner_fire_flush_cores,
	.write = _ocf_cleaner_fire_flush_cores,
};

static void _ocf_cleaner_core_io_end(struct ocf_request *rq)
{
	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	OCF_DEBUG_MSG(rq->cache, "Core writes finished");

	/*
	 * All cache read requests done, now we can submit writes to cores,
	 * Move processing to thread, where IO will be (and can be) submitted
	 */
	rq->io_if = &_io_if_flush_cores;
	ocf_engine_push_rq_front(rq, true);
}

static void _ocf_cleaner_core_io_cmpl(struct ocf_io *io, int error)
{
	struct ocf_map_info *map = io->priv1;
	struct ocf_request *rq = io->priv2;

	if (error) {
		map->invalid |= 1;
		_ocf_cleaner_set_error(rq);
		env_atomic_inc(&rq->cache->core_obj[map->core_id].counters->
				core_errors.write);
	}

	_ocf_cleaner_core_io_end(rq);

	ocf_io_put(io);
}

static void _ocf_cleaner_core_io_for_dirty_range(struct ocf_request *rq,
		struct ocf_map_info *iter, uint64_t begin, uint64_t end)
{
	uint64_t addr, offset;
	int err;
	struct ocf_cache *cache = rq->cache;
	struct ocf_io *io;
	struct ocf_counters_block *core_stats =
		&cache->core_obj[iter->core_id].counters->core_blocks;
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache,
			iter->coll_idx);

	io = ocf_new_core_io(cache, iter->core_id);
	if (!io)
		goto error;

	addr = (ocf_line_size(cache) * iter->core_line)
			+ SECTORS_TO_BYTES(begin);
	offset = (ocf_line_size(cache) * iter->hash_key)
			+ SECTORS_TO_BYTES(begin);

	ocf_io_configure(io, addr, SECTORS_TO_BYTES(end - begin), OCF_WRITE,
			part_id, 0);
	err = ocf_io_set_data(io, rq->data, offset);
	if (err) {
		ocf_io_put(io);
		goto error;
	}

	ocf_io_set_cmpl(io, iter, rq, _ocf_cleaner_core_io_cmpl);

	env_atomic64_add(SECTORS_TO_BYTES(end - begin), &core_stats->write_bytes);

	OCF_DEBUG_PARAM(rq->cache, "Core write, line = %llu, "
			"sector = %llu, count = %llu", iter->core_line, begin,
			end - begin);

	/* Increase IO counter to be processed */
	env_atomic_inc(&rq->req_remaining);

	/* Send IO */
	ocf_dobj_submit_io(io);

	return;
error:
	iter->invalid = true;
	_ocf_cleaner_set_error(rq);
}

static void _ocf_cleaner_core_submit_io(struct ocf_request *rq,
		struct ocf_map_info *iter)
{
	uint64_t i, dirty_start = 0;
	struct ocf_cache *cache = rq->cache;
	bool counting_dirty = false;

	/* Check integrity of entry to be cleaned */
	if (metadata_test_valid(cache, iter->coll_idx)
		&& metadata_test_dirty(cache, iter->coll_idx)) {

		_ocf_cleaner_core_io_for_dirty_range(rq, iter, 0,
				ocf_line_sectors(cache));

		return;
	}

	/* Sector cleaning, a little effort is required to this */
	for (i = 0; i < ocf_line_sectors(cache); i++) {
		if (!_ocf_cleaner_sector_is_dirty(cache, iter->coll_idx, i)) {
			if (counting_dirty) {
				counting_dirty = false;
				_ocf_cleaner_core_io_for_dirty_range(rq, iter,
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
		_ocf_cleaner_core_io_for_dirty_range(rq, iter, dirty_start, i);
}

static int _ocf_cleaner_fire_core(struct ocf_request *rq)
{
	uint32_t i;
	struct ocf_map_info *iter;

	OCF_DEBUG_TRACE(rq->cache);

	/* Protect IO completion race */
	env_atomic_set(&rq->req_remaining, 1);

	/* Submits writes to the core */
	for (i = 0; i < rq->core_line_count; i++) {
		iter = &(rq->map[i]);

		if (iter->invalid) {
			/* IO read error on cache, skip this item */
			continue;
		}

		if (iter->status == LOOKUP_MISS)
			continue;

		_ocf_cleaner_core_submit_io(rq, iter);
	}

	/* Protect IO completion race */
	_ocf_cleaner_core_io_end(rq);

	return 0;
}

static const struct ocf_io_if _io_if_fire_core = {
		.read = _ocf_cleaner_fire_core,
		.write = _ocf_cleaner_fire_core,
};

static void _ocf_cleaner_cache_io_end(struct ocf_request *rq)
{
	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	/*
	 * All cache read requests done, now we can submit writes to cores,
	 * Move processing to thread, where IO will be (and can be) submitted
	 */
	rq->io_if = &_io_if_fire_core;
	ocf_engine_push_rq_front(rq, true);

	OCF_DEBUG_MSG(rq->cache, "Cache reads finished");
}

static void _ocf_cleaner_cache_io_cmpl(struct ocf_io *io, int error)
{
	struct ocf_map_info *map = io->priv1;
	struct ocf_request *rq = io->priv2;

	if (error) {
		map->invalid |= 1;
		_ocf_cleaner_set_error(rq);
		env_atomic_inc(&rq->cache->core_obj[map->core_id].counters->
				cache_errors.read);
	}

	_ocf_cleaner_cache_io_end(rq);

	ocf_io_put(io);
}

/*
 * cleaner - Traverse cache lines to be cleaned, detect sequential IO, and
 * perform cache reads and core writes
 */
static int _ocf_cleaner_fire_cache(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;
	uint32_t i;
	struct ocf_map_info *iter = rq->map;
	uint64_t addr, offset;
	ocf_part_id_t part_id;
	struct ocf_io *io;
	int err;
	struct ocf_counters_block *cache_stats;

	/* Protect IO completion race */
	env_atomic_inc(&rq->req_remaining);

	for (i = 0; i < rq->core_line_count; i++, iter++) {
		if (iter->core_id == OCF_CORE_MAX)
			continue;
		if (iter->status == LOOKUP_MISS)
			continue;

		cache_stats = &cache->core_obj[iter->core_id].
				counters->cache_blocks;

		io = ocf_new_cache_io(cache);
		if (!io) {
			/* Allocation error */
			iter->invalid = true;
			_ocf_cleaner_set_error(rq);
			continue;
		}

		OCF_DEBUG_PARAM(rq->cache, "Cache read, line =  %u",
				iter->coll_idx);

		addr = ocf_metadata_map_lg2phy(cache,
				iter->coll_idx);
		addr *= ocf_line_size(cache);
		addr += cache->device->metadata_offset;

		offset = ocf_line_size(cache) * iter->hash_key;

		part_id = ocf_metadata_get_partition_id(cache, iter->coll_idx);

		ocf_io_set_cmpl(io, iter, rq, _ocf_cleaner_cache_io_cmpl);
		ocf_io_configure(io, addr, ocf_line_size(cache), OCF_READ,
				part_id, 0);
		err = ocf_io_set_data(io, rq->data, offset);
		if (err) {
			ocf_io_put(io);
			iter->invalid = true;
			_ocf_cleaner_set_error(rq);
			continue;
		}

		env_atomic64_add(ocf_line_size(cache), &cache_stats->read_bytes);

		ocf_dobj_submit_io(io);
	}

	/* Protect IO completion race */
	_ocf_cleaner_cache_io_end(rq);

	return 0;
}

static const struct ocf_io_if _io_if_fire_cache = {
		.read = _ocf_cleaner_fire_cache,
		.write = _ocf_cleaner_fire_cache,
};

static void _ocf_cleaner_on_resume(struct ocf_request *rq)
{
	OCF_DEBUG_TRACE(rq->cache);
	ocf_engine_push_rq_front(rq, true);
}

static int _ocf_cleaner_fire(struct ocf_request *rq)
{
	int result;

	/* Set resume call backs */
	rq->resume = _ocf_cleaner_on_resume;
	rq->io_if = &_io_if_fire_cache;

	/* Handle cache lines locks */
	result = _ocf_cleaner_cache_line_lock(rq);

	if (result >= 0) {
		if (result == OCF_LOCK_ACQUIRED) {
			OCF_DEBUG_MSG(rq->cache, "Lock acquired");
			_ocf_cleaner_fire_cache(rq);
		} else {
			OCF_DEBUG_MSG(rq->cache, "NO Lock");
		}
		return  0;
	} else {
		OCF_DEBUG_MSG(rq->cache, "Lock error");
	}

	return result;
}

/* Helper function for 'sort' */
static int _ocf_cleaner_cmp_private(const void *a, const void *b)
{
	struct ocf_map_info *_a = (struct ocf_map_info *)a;
	struct ocf_map_info *_b = (struct ocf_map_info *)b;

	static uint32_t step = 0;

	OCF_COND_RESCHED_DEFAULT(step);

	if (_a->core_id == _b->core_id)
		return (_a->core_line > _b->core_line) ? 1 : -1;

	return (_a->core_id > _b->core_id) ? 1 : -1;
}

/**
 * Prepare cleaning request to be fired
 *
 * @param rq cleaning request
 * @param i_out number of already filled map requests (remaining to be filled
 *    with missed
 */
static int _ocf_cleaner_do_fire(struct ocf_request *rq,  uint32_t i_out,
		bool do_sort)
{
	uint32_t i;
	/* Set counts of cache IOs */
	env_atomic_set(&rq->req_remaining, i_out);

	/* fill tail of a request with fake MISSes so that it won't
	 *  be cleaned
	 */
	for (; i_out < rq->core_line_count; ++i_out) {
		rq->map[i_out].core_id = OCF_CORE_MAX;
		rq->map[i_out].core_line = ULLONG_MAX;
		rq->map[i_out].status = LOOKUP_MISS;
		rq->map[i_out].hash_key = i_out;
	}

	if (do_sort) {
		/* Sort by core id and core line */
		env_sort(rq->map, rq->core_line_count, sizeof(rq->map[0]),
			_ocf_cleaner_cmp_private, NULL);
		for (i = 0; i < rq->core_line_count; i++)
			rq->map[i].hash_key = i;
	}

	/* issue actual request */
	return _ocf_cleaner_fire(rq);
}

static inline uint32_t _ocf_cleaner_get_rq_max_count(uint32_t count,
		bool low_mem)
{
	if (low_mem || count <= 4096)
		return count < 128 ? count : 128;

	return 1024;
}

static void _ocf_cleaner_fire_error(struct ocf_request *master,
		struct ocf_request *rq, int err)
{
	master->error = err;
	_ocf_cleaner_complete_rq(rq);
	_ocf_cleaner_dealloc_rq(rq);
}

/*
 * cleaner - Main function
 */
void ocf_cleaner_fire(struct ocf_cache *cache,
		const struct ocf_cleaner_attribs *attribs)
{
	uint32_t i, i_out = 0, count = attribs->count;
	/* max cache lines to be cleaned with one request: 1024 if over 4k lines
	 * to be flushed, otherwise 128. for large cleaning operations, 1024 is
	 * optimal number, but for smaller 1024 is too large to benefit from
	 * cleaning request overlapping
	 */
	uint32_t max = _ocf_cleaner_get_rq_max_count(count, false);
	ocf_cache_line_t cache_line;
	/* it is possible that more than one cleaning request will be generated
	 * for each cleaning order, thus multiple allocations. At the end of
	 * loop, rq is set to zero and NOT deallocated, as deallocation is
	 * handled in completion.
	 * In addition first request we call master which contains completion
	 * contexts. Then succeeding request we call salve requests which
	 * contains reference to the master request
	 */
	struct ocf_request *rq = NULL, *master;
	int err;
	ocf_core_id_t core_id;
	uint64_t core_sector;

	/* Allocate master request */
	master = _ocf_cleaner_alloc_master_rq(cache, max, attribs);

	if (!master) {
		/* Some memory allocation error, try re-allocate request */
		max = _ocf_cleaner_get_rq_max_count(count, true);
		master = _ocf_cleaner_alloc_master_rq(cache, max, attribs);
	}

	if (!master) {
		attribs->cmpl_fn(attribs->cmpl_context, -ENOMEM);
		return;
	}

	rq = master;

	/* prevent cleaning completion race */
	ocf_rq_get(master);
	env_atomic_inc(&master->master_remaining);

	for (i = 0; i < count; i++) {

		/* when request hasn't yet been allocated or is just issued */
		if (!rq) {
			if (max > count - i) {
				/* less than max left */
				max = count - i;
			}

			rq = _ocf_cleaner_alloc_slave_rq(master, max, attribs);
		}

		if (!rq) {
			/* Some memory allocation error,
			 * try re-allocate request
			 */
			max = _ocf_cleaner_get_rq_max_count(max, true);
			rq = _ocf_cleaner_alloc_slave_rq(master, max, attribs);
		}

		/* when request allocation failed stop processing */
		if (!rq) {
			master->error = -ENOMEM;
			break;
		}

		if (attribs->getter(cache, attribs->getter_context,
				i, &cache_line)) {
			OCF_DEBUG_MSG(cache, "Skip");
			continue;
		}

		/* when line already cleaned - rare condition under heavy
		 * I/O workload.
		 */
		if (!metadata_test_dirty(cache, cache_line)) {
			OCF_DEBUG_MSG(cache, "Not dirty");
			continue;
		}

		if (!metadata_test_valid_any(cache, cache_line)) {
			OCF_DEBUG_MSG(cache, "No any valid");

			/*
			 * Extremely disturbing cache line state
			 * Cache line (sector) cannot be dirty and not valid
			 */
			ENV_BUG();
			continue;
		}

		/* Get mapping info */
		ocf_metadata_get_core_info(cache, cache_line, &core_id,
				&core_sector);

		if (unlikely(!cache->core_obj[core_id].opened)) {
			OCF_DEBUG_MSG(cache, "Core object inactive");
			continue;
		}

		rq->map[i_out].core_id = core_id;
		rq->map[i_out].core_line = core_sector;
		rq->map[i_out].coll_idx = cache_line;
		rq->map[i_out].status = LOOKUP_HIT;
		rq->map[i_out].hash_key = i_out;
		i_out++;

		if (max == i_out) {
			err = _ocf_cleaner_do_fire(rq, i_out, attribs->do_sort);
			if (err) {
				_ocf_cleaner_fire_error(master, rq, err);
				rq  = NULL;
				break;
			}
			i_out = 0;
			rq  = NULL;
		}
	}

	if (rq) {
		err = _ocf_cleaner_do_fire(rq, i_out, attribs->do_sort);
		if (err)
			_ocf_cleaner_fire_error(master, rq, err);
		rq = NULL;
		i_out = 0;
	}

	/* prevent cleaning completion race */
	_ocf_cleaner_complete_rq(master);
	ocf_rq_put(master);
}

static void ocf_cleaner_sync_end(void *private_data, int error)
{
	struct ocf_cleaner_sync *sync = private_data;

	OCF_DEBUG_TRACE(rq->cache);
	if (error)
		sync->error = error;

	env_completion_complete(&sync->cmpl);
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

int ocf_cleaner_do_flush_data(struct ocf_cache *cache,
		struct flush_data *flush, uint32_t count,
		struct ocf_cleaner_attribs *attribs)
{
	struct ocf_cleaner_sync sync;

	env_completion_init(&sync.cmpl);
	sync.error = 0;
	attribs->cmpl_context = &sync;
	attribs->cmpl_fn = ocf_cleaner_sync_end;
	attribs->getter = _ocf_cleaner_do_flush_data_getter;
	attribs->getter_context = flush;
	attribs->count = count;

	ocf_cleaner_fire(cache, attribs);

	if (attribs->metadata_locked)
		OCF_METADATA_UNLOCK_WR();

	env_completion_wait(&sync.cmpl);

	if (attribs->metadata_locked)
		OCF_METADATA_LOCK_WR();

	attribs->cmpl_context = NULL;
	return sync.error;
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

void ocf_cleaner_sort_sectors(struct flush_data *tbl, uint32_t num)
{
	env_sort(tbl, num, sizeof(*tbl), _ocf_cleaner_cmp, _ocf_cleaner_swap);
}

void ocf_cleaner_sort_flush_containers(struct flush_container *fctbl,
		uint32_t num)
{
	int i;

	for (i = 0; i < num; i++) {
		env_sort(fctbl[i].flush_data, fctbl[i].count,
				sizeof(*fctbl[i].flush_data), _ocf_cleaner_cmp,
				_ocf_cleaner_swap);
	}
}
