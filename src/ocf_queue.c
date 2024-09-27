/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
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

static int _ocf_queue_create(ocf_cache_t cache, ocf_queue_t *queue,
		const struct ocf_queue_ops *ops)
{
	ocf_queue_t tmp_queue;
	int result;

	tmp_queue = env_zalloc(sizeof(*tmp_queue), ENV_MEM_NORMAL);
	if (!tmp_queue) {
		return -OCF_ERR_NO_MEM;
	}

	env_atomic_set(&tmp_queue->io_no, 0);
	result = env_spinlock_init(&tmp_queue->io_list_lock);
	if (result) {
		env_free(tmp_queue);
		return result;
	}

	INIT_LIST_HEAD(&tmp_queue->io_list_high);
	INIT_LIST_HEAD(&tmp_queue->io_list_low);
	env_atomic_set(&tmp_queue->ref_count, 1);
	tmp_queue->cache = cache;
	tmp_queue->ops = ops;

	*queue = tmp_queue;

	return 0;
}

int ocf_queue_create(ocf_cache_t cache, ocf_queue_t *queue,
		const struct ocf_queue_ops *ops)
{
	ocf_queue_t tmp_queue;
	int result;
	unsigned long flags = 0;

	OCF_CHECK_NULL(cache);

	result = ocf_mngt_cache_get(cache);
	if (result)
		return result;

	result = _ocf_queue_create(cache, &tmp_queue, ops);
	if (result) {
		ocf_mngt_cache_put(cache);
		return result;
	}

	result = ocf_queue_seq_cutoff_init(tmp_queue);
	if (result) {
		ocf_mngt_cache_put(cache);
		env_free(tmp_queue);
		return result;
	}

	env_spinlock_lock_irqsave(&cache->io_queues_lock, flags);
	list_add(&tmp_queue->list, &cache->io_queues);
	env_spinlock_unlock_irqrestore(&cache->io_queues_lock, flags);

	*queue = tmp_queue;

	return 0;
}

int ocf_queue_visit(ocf_cache_t cache, ocf_cache_queue_visitor_t visitor,
		void *ctx)
{
	ocf_queue_t queue;
	int result = 0;
	unsigned long flags = 0;

	env_spinlock_lock_irqsave(&cache->io_queues_lock, flags);

	list_for_each_entry(queue, &cache->io_queues, list) {
		result = visitor(queue, ctx);
		if (result)
			break;
	}

	env_spinlock_unlock_irqrestore(&cache->io_queues_lock, flags);

	return result;
}

int ocf_queue_create_mngt(ocf_cache_t cache, ocf_queue_t *queue,
		const struct ocf_queue_ops *ops)
{
	ocf_queue_t tmp_queue;
	int result;

	OCF_CHECK_NULL(cache);

	if (cache->mngt_queue)
		return -OCF_ERR_INVAL;

	result = ocf_mngt_cache_get(cache);
	if (result)
		return result;

	result = _ocf_queue_create(cache, &tmp_queue, ops);
	if (result) {
		ocf_mngt_cache_put(cache);
		return result;
	}

	cache->mngt_queue = tmp_queue;

	*queue = tmp_queue;

	return 0;
}

bool ocf_queue_is_mngt(ocf_queue_t queue)
{
	return queue == queue->cache->mngt_queue;
}

void ocf_queue_get(ocf_queue_t queue)
{
	OCF_CHECK_NULL(queue);

	env_atomic_inc(&queue->ref_count);
}

void ocf_queue_put(ocf_queue_t queue)
{
	ocf_cache_t cache = queue->cache;
	unsigned long flags = 0;

	OCF_CHECK_NULL(queue);

	if (env_atomic_dec_return(&queue->ref_count))
		return;

	queue->ops->stop(queue);
	if (!ocf_queue_is_mngt(queue)) {
		env_spinlock_lock_irqsave(&cache->io_queues_lock, flags);
		list_del(&queue->list);
		env_spinlock_unlock_irqrestore(&cache->io_queues_lock, flags);
		ocf_queue_seq_cutoff_deinit(queue);
	}
	ocf_mngt_cache_put(queue->cache);
	env_spinlock_destroy(&queue->io_list_lock);
	env_free(queue);
}

/* TODO: Remove opaque. It's not longer needed. */
void ocf_io_handle(ocf_io_t io, void *opaque)
{
	struct ocf_request *req = ocf_io_to_req(io);

	OCF_CHECK_NULL(req);

	req->engine_handler(req);
}

static struct ocf_request *ocf_queue_pop_req(ocf_queue_t q)
{
	unsigned long lock_flags = 0;
	struct ocf_request *req;
	struct list_head *io_list;

	OCF_CHECK_NULL(q);

	/* LOCK */
	env_spinlock_lock_irqsave(&q->io_list_lock, lock_flags);

	if (!list_empty(&q->io_list_high)) {
		io_list = &q->io_list_high;
	} else if (!list_empty(&q->io_list_low)) {
		io_list = &q->io_list_low;
	} else {	/* No items on the list */
		env_spinlock_unlock_irqrestore(&q->io_list_lock,
				lock_flags);
		return NULL;
	}

	/* Get the first request and remove it from the list */
	req = list_first_entry(io_list, struct ocf_request, list);

	env_atomic_dec(&q->io_no);
	list_del(&req->list);

	/* UNLOCK */
	env_spinlock_unlock_irqrestore(&q->io_list_lock, lock_flags);

	OCF_CHECK_NULL(req);

	return req;
}

void ocf_queue_run_single(ocf_queue_t q)
{
	struct ocf_request *io_req = NULL;

	OCF_CHECK_NULL(q);

	io_req = ocf_queue_pop_req(q);

	if (!io_req)
		return;

	if (io_req->io.handle)
		io_req->io.handle(io_req, io_req);
	else
		ocf_io_handle(io_req, io_req);
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

void ocf_queue_push_req(struct ocf_request *req, uint flags)
{
	ocf_cache_t cache = req->cache;
	ocf_queue_t q = NULL;
	unsigned long lock_flags = 0;
	struct list_head *io_list;

	INIT_LIST_HEAD(&req->list);

	ENV_BUG_ON(!req->io_queue);
	q = req->io_queue;

	if (!req->info.internal) {
		env_atomic_set(&cache->last_access_ms,
				env_ticks_to_msecs(env_get_tick_count()));
	}

	env_spinlock_lock_irqsave(&q->io_list_lock, lock_flags);

	io_list = (flags & OCF_QUEUE_PRIO_HIGH) ? &q->io_list_high : &q->io_list_low;
	list_add_tail(&req->list, io_list);
	env_atomic_inc(&q->io_no);

	env_spinlock_unlock_irqrestore(&q->io_list_lock, lock_flags);

	/* NOTE: do not dereference @req past this line, it might
	 * be picked up by concurrent io thread and deallocated
	 * at this point */

	ocf_queue_kick(q, (bool)(flags & OCF_QUEUE_ALLOW_SYNC));
}

void ocf_queue_push_req_cb(struct ocf_request *req,
		ocf_req_cb req_cb, uint flags)
{
	req->error = 0; /* Please explain why!!! */
	req->engine_handler = req_cb;
	ocf_queue_push_req(req, flags);
}
