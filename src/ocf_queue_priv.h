/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef OCF_QUEUE_PRIV_H_
#define OCF_QUEUE_PRIV_H_

#include "ocf_env.h"

struct ocf_queue {
	struct ocf_cache *cache;
	uint32_t id;

	env_atomic io_no;

	struct list_head io_list;
	env_spinlock io_list_lock;

	/* Tracing reference counter */
	env_atomic64 trace_ref_cntr;

	/* Tracing stop request */
	env_atomic trace_stop;

	void *priv;
};

int ocf_alloc_queues(struct ocf_cache *cache);

int ocf_start_queues(struct ocf_cache *cache);

void ocf_stop_queues(struct ocf_cache *cache);

void ocf_free_queues(struct ocf_cache *cache);

#endif
