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

static void ocf_init_queue(ocf_queue_t q)
{
	env_atomic_set(&q->io_no, 0);
	env_spinlock_init(&q->io_list_lock);
	INIT_LIST_HEAD(&q->io_list);
}

ocf_queue_t ocf_queue_alloc(ocf_cache_t cache, uint32_t id)
{
	ocf_queue_t queue;

	OCF_CHECK_NULL(cache);

	queue = env_zalloc(sizeof(*queue), ENV_MEM_NORMAL);
	if (!queue)
		return NULL;

	queue->cache = cache;
	ocf_init_queue(queue);

	queue->id = id;

	list_add(&queue->list, &cache->io_queues);

	return queue;
}

int ocf_queue_start(ocf_queue_t queue) {
	ocf_cache_t cache;

	OCF_CHECK_NULL(queue);

	cache = ocf_queue_get_cache(queue);

	return ctx_queue_init(cache->owner, queue);
}

void ocf_queue_free(ocf_queue_t queue)
{
	OCF_CHECK_NULL(queue);

	list_del(&queue->list);

	env_free(queue);
	queue = NULL;
}

void ocf_queue_stop(ocf_queue_t queue)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(queue);

	cache = ocf_queue_get_cache(queue);

	if (env_atomic_read(&queue->io_no) > 0)
		ocf_queue_run(queue);

	ctx_queue_stop(cache->owner, queue);
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
	ocf_cache_t cache;

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

uint32_t ocf_queue_get_id(ocf_queue_t q)
{
	OCF_CHECK_NULL(q);
	return q->id;
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
