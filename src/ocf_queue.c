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

int ocf_queue_create(ocf_cache_t cache, ocf_queue_t *queue,
		const struct ocf_queue_ops *ops)
{
	ocf_queue_t tmp_queue;
	int result;

	OCF_CHECK_NULL(cache);

	result = ocf_mngt_cache_get(cache);
	if (result)
		return result;

	tmp_queue = env_zalloc(sizeof(*tmp_queue), ENV_MEM_NORMAL);
	if (!tmp_queue) {
		ocf_mngt_cache_put(cache);
		return -OCF_ERR_NO_MEM;
	}

	env_atomic_set(&tmp_queue->io_no, 0);
	result = env_spinlock_init(&tmp_queue->io_list_lock);
	if (result) {
		ocf_mngt_cache_put(cache);
		env_free(tmp_queue);
		return result;
	}

	INIT_LIST_HEAD(&tmp_queue->io_list);
	env_atomic_set(&tmp_queue->ref_count, 1);
	tmp_queue->cache = cache;
	tmp_queue->ops = ops;

	result = ocf_queue_seq_cutoff_init(tmp_queue);
	if (result) {
		ocf_mngt_cache_put(cache);
		env_free(tmp_queue);
		return result;
	}

	list_add(&tmp_queue->list, &cache->io_queues);

	*queue = tmp_queue;

	return 0;
}

void ocf_queue_get(ocf_queue_t queue)
{
	OCF_CHECK_NULL(queue);

	env_atomic_inc(&queue->ref_count);
}

void ocf_queue_put(ocf_queue_t queue)
{
	OCF_CHECK_NULL(queue);

	if (env_atomic_dec_return(&queue->ref_count) == 0) {
		list_del(&queue->list);
		queue->ops->stop(queue);
		ocf_queue_seq_cutoff_deinit(queue);
		ocf_mngt_cache_put(queue->cache);
		env_spinlock_destroy(&queue->io_list_lock);
		env_free(queue);
	}
}

void ocf_io_handle(struct ocf_io *io, void *opaque)
{
	struct ocf_request *req = opaque;

	OCF_CHECK_NULL(req);

	req->engine_handler(req);
}

static struct ocf_request *ocf_queue_pop_req(ocf_queue_t q)
{
	unsigned long lock_flags = 0;
	struct ocf_request *req;

	OCF_CHECK_NULL(q);

	/* LOCK */
	env_spinlock_lock_irqsave(&q->io_list_lock, lock_flags);

	if (list_empty(&q->io_list)) {
		/* No items on the list */
		env_spinlock_unlock_irqrestore(&q->io_list_lock,
				lock_flags);
		return NULL;
	}

	/* Get the first request and remove it from the list */
	req = list_first_entry(&q->io_list, struct ocf_request, list);

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

	if (io_req->ioi.io.handle)
		io_req->ioi.io.handle(&io_req->ioi.io, io_req);
	else
		ocf_io_handle(&io_req->ioi.io, io_req);
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

void ocf_queue_push_req_back(struct ocf_request *req, bool allow_sync)
{
	ocf_cache_t cache = req->cache;
	ocf_queue_t q = NULL;
	unsigned long lock_flags = 0;

	INIT_LIST_HEAD(&req->list);

	ENV_BUG_ON(!req->io_queue);
	q = req->io_queue;

	if (!req->info.internal) {
		env_atomic_set(&cache->last_access_ms,
				env_ticks_to_msecs(env_get_tick_count()));
	}

	env_spinlock_lock_irqsave(&q->io_list_lock, lock_flags);

	list_add_tail(&req->list, &q->io_list);
	env_atomic_inc(&q->io_no);

	env_spinlock_unlock_irqrestore(&q->io_list_lock, lock_flags);

	/* NOTE: do not dereference @req past this line, it might
	 * be picked up by concurrent io thread and deallocated
	 * at this point */

	ocf_queue_kick(q, allow_sync);
}

void ocf_queue_push_req_front(struct ocf_request *req, bool allow_sync)
{
	ocf_cache_t cache = req->cache;
	ocf_queue_t q = NULL;
	unsigned long lock_flags = 0;

	ENV_BUG_ON(!req->io_queue);
	INIT_LIST_HEAD(&req->list);

	q = req->io_queue;

	if (!req->info.internal) {
		env_atomic_set(&cache->last_access_ms,
				env_ticks_to_msecs(env_get_tick_count()));
	}

	env_spinlock_lock_irqsave(&q->io_list_lock, lock_flags);

	list_add(&req->list, &q->io_list);
	env_atomic_inc(&q->io_no);

	env_spinlock_unlock_irqrestore(&q->io_list_lock, lock_flags);

	/* NOTE: do not dereference @req past this line, it might
	 * be picked up by concurrent io thread and deallocated
	 * at this point */

	ocf_queue_kick(q, allow_sync);
}

void ocf_queue_push_req_front_cb(struct ocf_request *req,
		ocf_req_cb req_cb,
		bool allow_sync)
{
	req->error = 0; /* Please explain why!!! */
	req->engine_handler = req_cb;
	ocf_queue_push_req_front(req, allow_sync);
}

void ocf_queue_push_req_back_cb(struct ocf_request *req,
		ocf_req_cb req_cb,
		bool allow_sync)
{
	req->error = 0; /* Please explain why!!! */
	req->engine_handler = req_cb;
	ocf_queue_push_req_back(req, allow_sync);
}
