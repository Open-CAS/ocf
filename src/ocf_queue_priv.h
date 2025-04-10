/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef OCF_QUEUE_PRIV_H_
#define OCF_QUEUE_PRIV_H_

#include "ocf_env.h"
#include "ocf_request.h"

/* ocf_queue_push_req flags */
#define	OCF_QUEUE_ALLOW_SYNC	0x01	/* Request can run immediately in caller context */
#define	OCF_QUEUE_PRIO_HIGH	0x02	/* Push to the high priority queue */

struct ocf_queue {
	ocf_cache_t cache;

	void *priv;

	struct list_head io_list_high;
	struct list_head io_list_low;

	/* per-queue free running global metadata lock index */
	unsigned lock_idx;

	/* per-queue free running lru list index */
	unsigned lru_idx;

	struct ocf_seq_cutoff *seq_cutoff;

	struct list_head list;

	const struct ocf_queue_ops *ops;

	/* Tracing reference counter */
	env_atomic64 trace_ref_cntr;

	/* Tracing stop request */
	env_atomic trace_stop;
	env_atomic io_no;

	env_atomic ref_count;
	env_spinlock io_list_lock;
} __attribute__((__aligned__(64)));

static inline void ocf_queue_kick(ocf_queue_t queue, bool allow_sync)
{
	if (allow_sync && queue->ops->kick_sync)
		queue->ops->kick_sync(queue);
	else
		queue->ops->kick(queue);
}

/**
 * @brief Push OCF request to the OCF thread worker queue
 *
 * @param req OCF request
 * @param flags See ocf_queue_push_req flags above
 */
void ocf_queue_push_req(struct ocf_request *req, uint flags);

/**
 * @brief Set interface and push from request to the OCF thread worker queue
 *
 * @param req OCF request
 * @param req_cb IO engine handler callback
 * @param flags See ocf_queue_push_req flags above
 */
void ocf_queue_push_req_cb(struct ocf_request *req,
		ocf_req_cb req_cb, uint flags);

#endif
