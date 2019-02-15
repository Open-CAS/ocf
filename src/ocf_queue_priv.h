/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef OCF_QUEUE_PRIV_H_
#define OCF_QUEUE_PRIV_H_

#include "ocf_env.h"

struct ocf_queue {
	ocf_cache_t cache;

	uint32_t id;

	env_atomic io_no;

	struct list_head io_list;
	env_spinlock io_list_lock;

	/* Tracing reference counter */
	env_atomic64 trace_ref_cntr;

	/* Tracing stop request */
	env_atomic trace_stop;

	struct list_head list;

	void *priv;
};

int ocf_alloc_queues(ocf_cache_t cache);

void ocf_free_queues(ocf_cache_t cache);

#endif
