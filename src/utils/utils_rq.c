/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "utils_rq.h"
#include "utils_cache_line.h"
#include "../ocf_request.h"
#include "../ocf_cache_priv.h"

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

enum ocf_rq_size {
	ocf_rq_size_1 = 0,
	ocf_rq_size_2,
	ocf_rq_size_4,
	ocf_rq_size_8,
	ocf_rq_size_16,
	ocf_rq_size_32,
	ocf_rq_size_64,
	ocf_rq_size_128,
	ocf_rq_size_max,
};

struct ocf_rq_allocator {
	env_allocator *allocator[ocf_rq_size_max];
	size_t size[ocf_rq_size_max];
};

static inline size_t ocf_rq_sizeof_map(struct ocf_request *rq)
{
	uint32_t lines = rq->alloc_core_line_count;
	size_t size = (lines * sizeof(struct ocf_map_info));

	ENV_BUG_ON(lines == 0);
	return size;
}

static inline size_t ocf_rq_sizeof(uint32_t lines)
{
	size_t size = sizeof(struct ocf_request) +
			(lines * sizeof(struct ocf_map_info));

	ENV_BUG_ON(lines == 0);
	return size;
}

#define ALLOCATOR_NAME_FMT "ocf_rq_%u"
/* Max number of digits in decimal representation of unsigned int is 10 */
#define ALLOCATOR_NAME_MAX (sizeof(ALLOCATOR_NAME_FMT) + 10)

int ocf_rq_allocator_init(struct ocf_ctx *ocf_ctx)
{
	int i;
	struct ocf_rq_allocator *rq;
	char name[ALLOCATOR_NAME_MAX] = { '\0' };

	OCF_DEBUG_TRACE(cache);

	ocf_ctx->resources.rq = env_zalloc(sizeof(*(ocf_ctx->resources.rq)),
			ENV_MEM_NORMAL);
	rq = ocf_ctx->resources.rq;

	if (!rq)
		goto ocf_utils_rq_init_ERROR;

	for (i = 0; i < ARRAY_SIZE(rq->allocator); i++) {
		rq->size[i] = ocf_rq_sizeof(1 << i);

		if (snprintf(name, sizeof(name), ALLOCATOR_NAME_FMT,
				(1 << i)) < 0) {
			goto ocf_utils_rq_init_ERROR;
		}

		rq->allocator[i] = env_allocator_create(rq->size[i], name);

		if (!rq->allocator[i])
			goto ocf_utils_rq_init_ERROR;

		OCF_DEBUG_PARAM(cache, "New request allocator, lines = %u, "
				"size = %lu", 1 << i, rq->size[i]);
	}

	return 0;

ocf_utils_rq_init_ERROR:

	ocf_rq_allocator_deinit(ocf_ctx);

	return -1;
}

void ocf_rq_allocator_deinit(struct ocf_ctx *ocf_ctx)
{
	int i;
	struct ocf_rq_allocator *rq;

	OCF_DEBUG_TRACE(cache);


	if (!ocf_ctx->resources.rq)
		return;

	rq = ocf_ctx->resources.rq;

	for (i = 0; i < ARRAY_SIZE(rq->allocator); i++) {
		if (rq->allocator[i]) {
			env_allocator_destroy(rq->allocator[i]);
			rq->allocator[i] = NULL;
		}
	}

	env_free(rq);
	ocf_ctx->resources.rq = NULL;
}

static inline env_allocator *_ocf_rq_get_allocator_1(
	struct ocf_cache *cache)
{
	return cache->owner->resources.rq->allocator[0];
}

static env_allocator *_ocf_rq_get_allocator(
	struct ocf_cache *cache, uint32_t count)
{
	struct ocf_ctx *ocf_ctx = cache->owner;
	unsigned int idx = 31 - __builtin_clz(count);

	if (__builtin_ffs(count) <= idx)
		idx++;

	ENV_BUG_ON(count == 0);

	if (idx >= ocf_rq_size_max)
		return NULL;

	return ocf_ctx->resources.rq->allocator[idx];
}

static void start_cache_req(struct ocf_request *rq)
{
	ocf_cache_t cache = rq->cache;

	rq->d2c = 1;
	if (env_atomic_read(&cache->attached)) {
		rq->d2c = 0		;
		env_atomic_inc(&cache->pending_cache_requests);
		if (!env_atomic_read(&cache->attached)) {
			rq->d2c = 1;
			env_atomic_dec(&cache->pending_cache_requests);
		}
	}
}

struct ocf_request *ocf_rq_new(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t addr, uint32_t bytes, int rw)
{
	uint64_t core_line_first, core_line_last, core_line_count;
	struct ocf_request *rq;
	env_allocator *allocator;

	if (likely(bytes)) {
		core_line_first = ocf_bytes_2_lines(cache, addr);
		core_line_last = ocf_bytes_2_lines(cache, addr + bytes - 1);
		core_line_count = core_line_last - core_line_first + 1;
	} else {
		core_line_first = ocf_bytes_2_lines(cache, addr);
		core_line_last = core_line_first;
		core_line_count = 1;
	}

	allocator = _ocf_rq_get_allocator(cache, core_line_count);
	if (allocator) {
		rq = env_allocator_new(allocator);
	} else {
		rq = env_allocator_new(_ocf_rq_get_allocator_1(cache));
	}

	if (unlikely(!rq))
		return NULL;

	if (allocator)
		rq->map = rq->__map;

	OCF_DEBUG_TRACE(cache);

	rq->cache = cache;

	env_atomic_inc(&cache->pending_requests);
	start_cache_req(rq);

	rq->io_queue = 0;
	env_atomic_set(&rq->ref_count, 1);
	rq->core_id = core_id;

	rq->byte_position = addr;
	rq->byte_length = bytes;
	rq->core_line_first = core_line_first;
	rq->core_line_last = core_line_last;
	rq->core_line_count = core_line_count;
	rq->alloc_core_line_count = core_line_count;
	rq->rw = rw;
	rq->part_id = PARTITION_DEFAULT;

	return rq;
}

int ocf_rq_alloc_map(struct ocf_request *rq)
{
	if (rq->map)
		return 0;

	rq->map = env_zalloc(ocf_rq_sizeof_map(rq), ENV_MEM_NOIO);
	if (!rq->map) {
		rq->error = -ENOMEM;
		return -ENOMEM;
	}

	return 0;
}

struct ocf_request *ocf_rq_new_extended(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t addr, uint32_t bytes, int rw)
{
	struct ocf_request *rq;

	rq = ocf_rq_new(cache, core_id, addr, bytes, rw);

	if (likely(rq) && ocf_rq_alloc_map(rq)) {
		ocf_rq_put(rq);
		return NULL;
	}

	return rq;
}

struct ocf_request *ocf_rq_new_discard(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t addr, uint32_t bytes, int rw)
{
	struct ocf_request *rq;

	rq = ocf_rq_new_extended(cache, core_id, addr,
			MIN(bytes, MAX_TRIM_RQ_SIZE),rw);

	if (!rq)
		return NULL;

	rq->discard.sector = BYTES_TO_SECTORS(addr);
	rq->discard.nr_sects = BYTES_TO_SECTORS(bytes);
	rq->discard.handled = 0;

	return rq;
}

void ocf_rq_get(struct ocf_request *rq)
{
	OCF_DEBUG_TRACE(rq->cache);

	env_atomic_inc(&rq->ref_count);
}

void ocf_rq_put(struct ocf_request *rq)
{
	env_allocator *allocator;

	if (env_atomic_dec_return(&rq->ref_count))
		return;

	OCF_DEBUG_TRACE(rq->cache);

	if (!rq->d2c && !env_atomic_dec_return(
			&rq->cache->pending_cache_requests)) {
		env_waitqueue_wake_up(&rq->cache->pending_cache_wq);
	}

	env_atomic_dec(&rq->cache->pending_requests);

	allocator = _ocf_rq_get_allocator(rq->cache,
			rq->alloc_core_line_count);
	if (allocator) {
		env_allocator_del(allocator, rq);
	} else {
		env_free(rq->map);
		env_allocator_del(_ocf_rq_get_allocator_1(rq->cache), rq);
	}
}

void ocf_rq_clear_info(struct ocf_request *rq)
{
	ENV_BUG_ON(env_memset(&rq->info, sizeof(rq->info), 0));
}

void ocf_rq_clear_map(struct ocf_request *rq)
{
	if (likely(rq->map))
		ENV_BUG_ON(env_memset(rq->map,
			   sizeof(rq->map[0]) * rq->core_line_count, 0));
}

uint32_t ocf_rq_get_allocated(struct ocf_cache *cache)
{
	return env_atomic_read(&cache->pending_requests);
}
