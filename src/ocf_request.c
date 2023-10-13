/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_request.h"
#include "ocf_cache_priv.h"
#include "concurrency/ocf_metadata_concurrency.h"
#include "engine/engine_common.h"
#include "utils/utils_cache_line.h"

#define OCF_UTILS_RQ_DEBUG 0

#if 1 == OCF_UTILS_RQ_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Utils][RQ] %s\n", __func__)

#define OCF_DEBUG_PARAM(cache, format, ...) \
	ocf_cache_log(cache, log_info, "[Utils][RQ] %s - "format"\n", \
			__func__, ##__VA_ARGS__)
#else
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_PARAM(cache, format, ...)
#endif

enum ocf_req_size {
	ocf_req_size_1 = 0,
	ocf_req_size_2,
	ocf_req_size_4,
	ocf_req_size_8,
	ocf_req_size_16,
	ocf_req_size_32,
	ocf_req_size_64,
	ocf_req_size_128,
};

static inline size_t ocf_req_sizeof_map(uint32_t lines)
{
	size_t size = (lines * sizeof(struct ocf_map_info));

	ENV_BUG_ON(lines == 0);
	return size;
}

static inline size_t ocf_req_sizeof_alock_status(uint32_t lines)
{
	uint32_t size;

	ENV_BUG_ON(lines == 0);

	/* 1 bit per cacheline */
	size = OCF_DIV_ROUND_UP(lines, 8);

	/* round up to 8B to avoid out of boundary access in bit operations
	 * on alock status */
	return OCF_DIV_ROUND_UP(size, sizeof(long)) * sizeof(long);
}

int ocf_req_allocator_init(struct ocf_ctx *ocf_ctx)
{
	enum ocf_req_size max_req_size = ocf_req_size_128;
	size_t alock_status_size = ocf_req_sizeof_alock_status(
			(1U << (unsigned)max_req_size));
	size_t header_size = sizeof(struct ocf_request) + alock_status_size;

	ocf_ctx->resources.req = env_mpool_create(header_size,
		sizeof(struct ocf_map_info), ENV_MEM_NORMAL, max_req_size,
		false, NULL, "ocf_req", true);

	if (ocf_ctx->resources.req == NULL)
		return -1;

	return 0;
}

void ocf_req_allocator_deinit(struct ocf_ctx *ocf_ctx)
{
	env_mpool_destroy(ocf_ctx->resources.req);
	ocf_ctx->resources.req = NULL;
}

static inline void ocf_req_init(struct ocf_request *req, ocf_cache_t cache,
		ocf_queue_t queue, ocf_core_t core,
		uint64_t addr, uint32_t bytes, int rw)
{
	req->io_queue = queue;

	req->core = core;
	req->cache = cache;

	env_atomic_set(&req->ref_count, 1);

	req->byte_position = addr;
	req->byte_length = bytes;
	req->rw = rw;
}

struct ocf_request *ocf_req_new_mngt(ocf_cache_t cache, ocf_queue_t queue)
{
	struct ocf_request *req;

	req = env_zalloc(sizeof(*req), ENV_MEM_NORMAL);
	if (unlikely(!req))
		return NULL;

	ocf_queue_get(queue);

	ocf_req_init(req, cache, queue, NULL, 0, 0, 0);

	req->is_mngt = true;

	return req;
}

struct ocf_request *ocf_req_new_cleaner(ocf_cache_t cache, ocf_queue_t queue,
		uint32_t count)
{
	struct ocf_request *req;
	bool map_allocated = true, is_mngt = false;

	if (!ocf_refcnt_inc(&cache->refcnt.metadata))
		return NULL;

	if (unlikely(ocf_queue_is_mngt(queue))) {
		req = env_zalloc(sizeof(*req) + ocf_req_sizeof_map(count) +
				ocf_req_sizeof_alock_status(count),
				ENV_MEM_NORMAL);
		is_mngt = true;
	} else {
		req = env_mpool_new(cache->owner->resources.req, count);
		if (!req) {
			map_allocated = false;
			req = env_mpool_new(cache->owner->resources.req, 1);
		}
	}

	if (!req) {
		ocf_refcnt_dec(&cache->refcnt.metadata);
		return NULL;
	}
	req->is_mngt = is_mngt;

	ocf_queue_get(queue);

	ocf_req_init(req, cache, queue, NULL, 0, 0, OCF_READ);

	if (map_allocated) {
		req->map = req->__map;
		req->alock_status = (uint8_t*)&req->__map[count];
		req->alloc_core_line_count = count;
	} else {
		req->alloc_core_line_count = 1;
	}
	req->core_line_count = count;
	req->lock_idx = ocf_metadata_concurrency_next_idx(queue);
	req->cleaner = true;

	if (ocf_req_alloc_map(req)) {
		ocf_req_put(req);
		req = NULL;
	}
	return req;
}

static inline struct ocf_request *ocf_req_new_d2c(ocf_queue_t queue,
		ocf_core_t core, uint64_t addr, uint32_t bytes, int rw)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	struct ocf_request *req;

	req = env_mpool_new(cache->owner->resources.req, 1);
	if (unlikely(!req))
		        return NULL;

	ocf_req_init(req, cache, queue, core, addr, bytes, rw);

	req->d2c = true;
	return req;
}

struct ocf_request *ocf_req_new(ocf_queue_t queue, ocf_core_t core,
		uint64_t addr, uint32_t bytes, int rw)
{
	uint64_t core_line_first, core_line_last, core_line_count;
	ocf_cache_t cache = ocf_core_get_cache(core);
	struct ocf_request *req;
	bool map_allocated = true;

	ENV_BUG_ON(ocf_queue_is_mngt(queue));

	ocf_queue_get(queue);

	if (!ocf_refcnt_inc(&cache->refcnt.metadata)) {
		if (!ocf_refcnt_inc(&cache->refcnt.d2c))
			ENV_BUG();
		req = ocf_req_new_d2c(queue, core, addr, bytes, rw);
		if (unlikely(!req)) {
			ocf_queue_put(queue);
			return NULL;
		}
		return req;
	}

	if (likely(bytes)) {
		core_line_first = ocf_bytes_2_lines(cache, addr);
		core_line_last = ocf_bytes_2_lines(cache, addr + bytes - 1);
		core_line_count = core_line_last - core_line_first + 1;
	} else {
		core_line_first = ocf_bytes_2_lines(cache, addr);
		core_line_last = core_line_first;
		core_line_count = 1;
	}

	req = env_mpool_new(cache->owner->resources.req, core_line_count);
	if (!req) {
		map_allocated = false;
		req = env_mpool_new(cache->owner->resources.req, 1);
	}

	if (unlikely(!req)) {
		ocf_refcnt_dec(&cache->refcnt.metadata);
		ocf_queue_put(queue);
		return NULL;
	}

	if (map_allocated) {
		req->map = req->__map;
		req->alock_status = (uint8_t*)&req->__map[core_line_count];
		req->alloc_core_line_count = core_line_count;
	} else {
		req->alloc_core_line_count = 1;
	}

	OCF_DEBUG_TRACE(cache);

	ocf_req_init(req, cache, queue, NULL, addr, bytes, rw);

	req->core_line_first = core_line_first;
	req->core_line_last = core_line_last;
	req->core_line_count = core_line_count;

	req->discard.sector = BYTES_TO_SECTORS(addr);
	req->discard.nr_sects = BYTES_TO_SECTORS(bytes);
	req->discard.handled = 0;

	req->part_id = PARTITION_DEFAULT;

	req->lock_idx = ocf_metadata_concurrency_next_idx(queue);

	return req;
}

struct ocf_request *ocf_req_new_cache(ocf_cache_t cache, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, int rw)
{
	uint64_t core_line_first, core_line_last, core_line_count;
	struct ocf_request *req;
	bool map_allocated = true;

	ENV_BUG_ON(ocf_queue_is_mngt(queue));

	if (!ocf_refcnt_inc(&cache->refcnt.metadata))
		return NULL;

	ocf_queue_get(queue);

	if (likely(bytes)) {
		core_line_first = ocf_bytes_2_lines(cache, addr);
		core_line_last = ocf_bytes_2_lines(cache, addr + bytes - 1);
		core_line_count = core_line_last - core_line_first + 1;
	} else {
		core_line_count = 1;
	}

	req = env_mpool_new(cache->owner->resources.req, core_line_count);
	if (!req) {
		map_allocated = false;
		req = env_mpool_new(cache->owner->resources.req, 1);
	}

	if (unlikely(!req)) {
		ocf_refcnt_dec(&cache->refcnt.metadata);
		ocf_queue_put(queue);
		return NULL;
	}

	if (map_allocated) {
		req->map = req->__map;
		req->alock_status = (uint8_t *)&req->__map[core_line_count];
		req->alloc_core_line_count = core_line_count;
	} else {
		req->alloc_core_line_count = 1;
	}

	ocf_req_init(req, cache, queue, NULL, addr, bytes, rw);

	req->lock_idx = ocf_metadata_concurrency_next_idx(queue);

	return req;
}

int ocf_req_alloc_map(struct ocf_request *req)
{
	uint32_t lines = req->core_line_count;

	if (req->map)
		return 0;

	req->map = env_zalloc(ocf_req_sizeof_map(lines) +
			ocf_req_sizeof_alock_status(req->core_line_count),
			ENV_MEM_NOIO);
	if (!req->map) {
		req->error = -OCF_ERR_NO_MEM;
		return -OCF_ERR_NO_MEM;
	}

	req->alock_status = &((uint8_t*)req->map)[ocf_req_sizeof_map(lines)];

	return 0;
}

int ocf_req_alloc_map_discard(struct ocf_request *req)
{
	ENV_BUILD_BUG_ON(MAX_TRIM_RQ_SIZE / ocf_cache_line_size_4 *
			sizeof(struct ocf_map_info) > 4 * KiB);

	if (req->byte_length <= MAX_TRIM_RQ_SIZE)
		return ocf_req_alloc_map(req);

	/*
	 * NOTE: For cache line size bigger than 8k a single-allocation mapping
	 * can handle more than MAX_TRIM_RQ_SIZE, so for these cache line sizes
	 * discard request uses only part of the mapping array.
	 */
	req->byte_length = MAX_TRIM_RQ_SIZE;
	req->core_line_last = ocf_bytes_2_lines(req->cache,
			req->byte_position + req->byte_length - 1);
	req->core_line_count = req->core_line_last - req->core_line_first + 1;

	return ocf_req_alloc_map(req);
}

struct ocf_request *ocf_req_new_extended(ocf_queue_t queue, ocf_core_t core,
		uint64_t addr, uint32_t bytes, int rw)
{
	struct ocf_request *req;

	req = ocf_req_new(queue, core, addr, bytes, rw);

	if (likely(req) && ocf_req_alloc_map(req)) {
		ocf_req_put(req);
		return NULL;
	}

	return req;
}

struct ocf_request *ocf_req_new_discard(ocf_queue_t queue, ocf_core_t core,
		uint64_t addr, uint32_t bytes, int rw)
{
	struct ocf_request *req;

	req = ocf_req_new_extended(queue, core, addr,
			OCF_MIN(bytes, MAX_TRIM_RQ_SIZE), rw);
	if (!req)
		return NULL;

	return req;
}

void ocf_req_get(struct ocf_request *req)
{
	OCF_DEBUG_TRACE(req->cache);

	env_atomic_inc(&req->ref_count);
}

void ocf_req_put(struct ocf_request *req)
{
	ocf_queue_t queue = req->io_queue;

	if (env_atomic_dec_return(&req->ref_count))
		return;

	OCF_DEBUG_TRACE(req->cache);

	if (req->d2c)
		ocf_refcnt_dec(&req->cache->refcnt.d2c);
	else if (!req->is_mngt || req->cleaner)
		ocf_refcnt_dec(&req->cache->refcnt.metadata);

	if (unlikely(req->is_mngt)) {
		env_free(req);
	} else {
		if (req->map != req->__map)
			env_free(req->map);
		env_mpool_del(req->cache->owner->resources.req, req,
				req->alloc_core_line_count);
	}

	ocf_queue_put(queue);
}

int ocf_req_set_dirty(struct ocf_request *req)
{
	req->dirty = !!ocf_refcnt_inc(&req->cache->refcnt.dirty);
	return req->dirty ? 0 : -OCF_ERR_AGAIN;
}

void ocf_req_clear_info(struct ocf_request *req)
{
	ENV_BUG_ON(env_memset(&req->info, sizeof(req->info), 0));
}

void ocf_req_clear_map(struct ocf_request *req)
{
	if (likely(req->map))
		ENV_BUG_ON(env_memset(req->map,
			   sizeof(req->map[0]) * req->core_line_count, 0));
}

void ocf_req_hash(struct ocf_request *req)
{
	int i;

	for (i = 0; i < req->core_line_count; i++) {
		req->map[i].hash = ocf_metadata_hash_func(req->cache,
				req->core_line_first + i,
				ocf_core_get_id(req->core));
	}
}

void ocf_req_forward_cache_io(struct ocf_request *req, int dir, uint64_t addr,
		uint64_t bytes, uint64_t offset)
{
	ocf_volume_t volume = ocf_cache_get_volume(req->cache);
	ocf_forward_token_t token = ocf_req_to_cache_forward_token(req);

	req->cache_error = 0;

	ocf_req_forward_cache_get(req);
	ocf_volume_forward_io(volume, token, dir, addr, bytes, offset);
}

void ocf_req_forward_cache_flush(struct ocf_request *req)
{
	ocf_volume_t volume = ocf_cache_get_volume(req->cache);
	ocf_forward_token_t token = ocf_req_to_cache_forward_token(req);

	req->cache_error = 0;

	ocf_req_forward_cache_get(req);
	ocf_volume_forward_flush(volume, token);
}

void ocf_req_forward_cache_discard(struct ocf_request *req, uint64_t addr,
		uint64_t bytes)
{
	ocf_volume_t volume = ocf_cache_get_volume(req->cache);
	ocf_forward_token_t token = ocf_req_to_cache_forward_token(req);

	req->cache_error = 0;

	ocf_req_forward_cache_get(req);
	ocf_volume_forward_discard(volume, token, addr, bytes);
}

void ocf_req_forward_cache_write_zeros(struct ocf_request *req, uint64_t addr,
		uint64_t bytes)
{
	ocf_volume_t volume = ocf_cache_get_volume(req->cache);
	ocf_forward_token_t token = ocf_req_to_cache_forward_token(req);

	req->cache_error = 0;

	ocf_req_forward_cache_get(req);
	ocf_volume_forward_write_zeros(volume, token, addr, bytes);
}

void ocf_req_forward_cache_metadata(struct ocf_request *req, int dir,
		uint64_t addr, uint64_t bytes, uint64_t offset)
{
	ocf_volume_t volume = ocf_cache_get_volume(req->cache);
	ocf_forward_token_t token = ocf_req_to_cache_forward_token(req);

	req->cache_error = 0;

	ocf_req_forward_cache_get(req);
	ocf_volume_forward_metadata(volume, token, dir, addr, bytes, offset);
}

void ocf_req_forward_core_io(struct ocf_request *req, int dir, uint64_t addr,
		uint64_t bytes, uint64_t offset)
{
	ocf_volume_t volume = ocf_core_get_volume(req->core);
	ocf_forward_token_t token = ocf_req_to_core_forward_token(req);

	req->core_error = 0;

	ocf_req_forward_core_get(req);
	ocf_volume_forward_io(volume, token, dir, addr, bytes, offset);
}

void ocf_req_forward_core_flush(struct ocf_request *req)
{
	ocf_volume_t volume = ocf_core_get_volume(req->core);
	ocf_forward_token_t token = ocf_req_to_core_forward_token(req);

	req->core_error = 0;

	ocf_req_forward_core_get(req);
	ocf_volume_forward_flush(volume, token);
}

void ocf_req_forward_core_discard(struct ocf_request *req, uint64_t addr,
		uint64_t bytes)
{
	ocf_volume_t volume = ocf_core_get_volume(req->core);
	ocf_forward_token_t token = ocf_req_to_core_forward_token(req);

	req->core_error = 0;

	ocf_req_forward_core_get(req);
	ocf_volume_forward_discard(volume, token, addr, bytes);
}

struct ocf_io *ocf_forward_get_io(ocf_forward_token_t token)
{
	struct ocf_request *req = (struct ocf_request *)(token & ~1);

	return &req->ioi.io;
}

static inline void _ocf_forward_get(ocf_forward_token_t token)
{
	struct ocf_request *req = (struct ocf_request *)(token & ~1);

	if (token & 1)
		ocf_req_forward_cache_get(req);
	else
		ocf_req_forward_core_get(req);
}

void ocf_forward_get(ocf_forward_token_t token)
{
	_ocf_forward_get(token);
}

void ocf_forward_io(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset)
{
	_ocf_forward_get(token);
	ocf_volume_forward_io(volume, token, dir, addr, bytes, offset);
}

void ocf_forward_flush(ocf_volume_t volume, ocf_forward_token_t token)
{
	_ocf_forward_get(token);
	ocf_volume_forward_flush(volume, token);
}

void ocf_forward_discard(ocf_volume_t volume, ocf_forward_token_t token,
		uint64_t addr, uint64_t bytes)
{
	_ocf_forward_get(token);
	ocf_volume_forward_discard(volume, token, addr, bytes);
}

void ocf_forward_write_zeros(ocf_volume_t volume, ocf_forward_token_t token,
		uint64_t addr, uint64_t bytes)
{
	_ocf_forward_get(token);
	ocf_volume_forward_write_zeros(volume, token, addr, bytes);
}

void ocf_forward_metadata(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset)
{
	_ocf_forward_get(token);
	ocf_volume_forward_metadata(volume, token, dir, addr, bytes, offset);
}

void ocf_forward_end(ocf_forward_token_t token, int error)
{
	struct ocf_request *req = ocf_req_forward_token_to_req(token);

	req->error |= error;

	if (token & 1) {
		req->cache_error = req->cache_error ?: error;
		ocf_req_forward_cache_put(req);
	} else {
		req->core_error = req->core_error ?: error;
		ocf_req_forward_core_put(req);
	}
}
