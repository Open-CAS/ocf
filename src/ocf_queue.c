/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "ocf/ocf.h"
#include "ocf/ocf_queue.h"
#include "ocf_priv.h"
#include "ocf_queue_priv.h"
#include "ocf_cache_priv.h"
#include "ocf_ctx_priv.h"
#include "ocf_request.h"
#include "mngt/ocf_mngt_common.h"
#include "engine/cache_engine.h"
#include "ocf_def_priv.h"

int ocf_alloc_queues(struct ocf_cache *cache)
{
	ENV_BUG_ON(!cache->io_queues_no);

	cache->io_queues = env_zalloc(
		sizeof(*cache->io_queues) * cache->io_queues_no, ENV_MEM_NORMAL);
	if (!cache->io_queues)
		return -ENOMEM;

	return 0;
}

void ocf_free_queues(struct ocf_cache *cache)
{
	env_free(cache->io_queues);
	cache->io_queues_no = 0;
	cache->io_queues = NULL;
}

static void ocf_init_queue(struct ocf_queue *q)
{
	env_atomic_set(&q->io_no, 0);
	env_spinlock_init(&q->io_list_lock);
	INIT_LIST_HEAD(&q->io_list);
}

int ocf_start_queues(struct ocf_cache *cache)
{
	int id, result = 0;
	struct ocf_queue *q;

	for (id = 0; id < cache->io_queues_no; id++) {
		q = &cache->io_queues[id];
		q->cache = cache;
		q->id = id;
		ocf_init_queue(q);
		result = ctx_queue_init(cache->owner, q);
		if (result)
			break;
	}
	if (result) {
		while (id) {
			ctx_queue_stop(cache->owner,
					&cache->io_queues[--id]);
		}
	}

	return result;
}

void ocf_stop_queues(struct ocf_cache *dev)
{
	int i;
	struct ocf_queue *curr;

	ocf_mngt_wait_for_io_finish(dev);

	/* Stop IO threads. */
	for (i = 0 ; i < dev->io_queues_no; i++) {
		curr = &dev->io_queues[i];
		ctx_queue_stop(dev->owner, curr);
	}
}

void ocf_io_handle(struct ocf_io *io, void *opaque)
{
	struct ocf_request *req = opaque;

	OCF_CHECK_NULL(req);

	if (req->rw == OCF_WRITE)
		req->io_if->write(req);
	else
		req->io_if->read(req);
}

void ocf_queue_run_single(ocf_queue_t q)
{
	struct ocf_request *io_req = NULL;
	struct ocf_cache *cache;

	OCF_CHECK_NULL(q);

	cache = q->cache;

	io_req = ocf_engine_pop_req(cache, q);

	if (!io_req)
		return;

	if (io_req->io && io_req->io->handle)
		io_req->io->handle(io_req->io, io_req);
	else
		ocf_io_handle(io_req->io, io_req);
}

void ocf_queue_run(ocf_queue_t q)
{
	unsigned char step = 0;

	OCF_CHECK_NULL(q);

	while (env_atomic_read(&q->io_no) > 0) {
		ocf_queue_run_single(q);

		OCF_COND_RESCHED(step, 128);
	}
}

void ocf_queue_set_priv(ocf_queue_t q, void *priv)
{
	OCF_CHECK_NULL(q);
	q->priv = priv;
}

void *ocf_queue_get_priv(ocf_queue_t q)
{
	OCF_CHECK_NULL(q);
	return q->priv;
}

uint32_t ocf_queue_pending_io(ocf_queue_t q)
{
	OCF_CHECK_NULL(q);
	return env_atomic_read(&q->io_no);
}

ocf_cache_t ocf_queue_get_cache(ocf_queue_t q)
{
	OCF_CHECK_NULL(q);
	return q->cache;
}

uint32_t ocf_queue_get_id(ocf_queue_t q)
{
	OCF_CHECK_NULL(q);
	return q->id;
}

int ocf_cache_get_queue(ocf_cache_t cache, unsigned id, ocf_queue_t *q)
{
	OCF_CHECK_NULL(cache);

	if (!q || id >= cache->io_queues_no)
		return -OCF_ERR_INVAL;

	*q = &cache->io_queues[id];
	return 0;
}
