/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef OCF_QUEUE_PRIV_H_
#define OCF_QUEUE_PRIV_H_

#include "ocf_env.h"

struct ocf_queue {
	ocf_cache_t cache;

	env_atomic io_no;

	env_atomic ref_count;

	struct list_head io_list;
	env_spinlock io_list_lock;

	/* Tracing reference counter */
	env_atomic64 trace_ref_cntr;

	/* Tracing stop request */
	env_atomic trace_stop;

	struct list_head list;

	const struct ocf_queue_ops *ops;

	void *priv;
};

static inline void ocf_queue_kick(ocf_queue_t queue, bool allow_sync)
{
	if (allow_sync && queue->ops->kick_sync)
		queue->ops->kick_sync(queue);
	else
		queue->ops->kick(queue);
}

#endif
