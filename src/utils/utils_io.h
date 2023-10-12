/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef UTILS_IO_H_
#define UTILS_IO_H_

#include "../ocf_request.h"

typedef void (*ocf_submit_end_t)(void *priv, int error);

void ocf_submit_cache_flush(ocf_cache_t cache,
		ocf_submit_end_t cmpl, void *priv);

void ocf_submit_cache_discard(ocf_cache_t cache, uint64_t addr,
		uint64_t length, ocf_submit_end_t cmpl, void *priv);

void ocf_submit_cache_write_zeros(ocf_cache_t cache, uint64_t addr,
		uint64_t length, ocf_submit_end_t cmpl, void *priv);

void ocf_submit_cache_page(ocf_cache_t cache, uint64_t addr, int dir,
		void *buffer, ocf_submit_end_t cmpl, void *priv);

static inline struct ocf_io *ocf_new_cache_io(ocf_cache_t cache,
		ocf_queue_t queue, uint64_t addr, uint32_t bytes,
		uint32_t dir, uint32_t io_class, uint64_t flags)

{
	return ocf_volume_new_io(ocf_cache_get_volume(cache), queue,
			addr, bytes, dir, io_class, flags);
}

static inline struct ocf_io *ocf_new_core_io(ocf_core_t core,
		ocf_queue_t queue, uint64_t addr, uint32_t bytes,
		uint32_t dir, uint32_t io_class, uint64_t flags)
{
	return ocf_volume_new_io(ocf_core_get_volume(core), queue,
			addr, bytes, dir, io_class, flags);
}

#endif /* UTILS_IO_H_ */
