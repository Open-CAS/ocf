/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PIO_CONCURRENCY_H_
#define __OCF_PIO_CONCURRENCY_H_

#include "../utils/utils_alock.h"

int ocf_pio_async_lock(struct ocf_alock *alock, struct ocf_request *req,
		ocf_req_async_lock_cb cmpl);

void ocf_pio_async_unlock(struct ocf_alock *alock, struct ocf_request *req);

int ocf_pio_concurrency_init(struct ocf_alock **self, ocf_cache_t cache);

void ocf_pio_concurrency_deinit(struct ocf_alock **self);

#endif
