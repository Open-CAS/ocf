/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_IO_PRIV_H__
#define __OCF_IO_PRIV_H__

#include "ocf/ocf.h"
#include "utils/utils_io_allocator.h"

int ocf_io_allocator_default_init(ocf_io_allocator_t allocator,
		const char *name);

void ocf_io_allocator_default_deinit(ocf_io_allocator_t allocator);

void *ocf_io_allocator_default_new(ocf_io_allocator_t allocator,
		ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir);

void ocf_io_allocator_default_del(ocf_io_allocator_t allocator, void *obj);

ocf_io_t ocf_io_new(ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir,
		uint32_t io_class, uint64_t flags);


void ocf_io_end_func(ocf_io_t io, int error);

#define ocf_io_end(_io, _error)                                 \
	do {                                            \
		OCF_BLKTRACE_COMPLETE_IO(_io);          \
		ocf_io_end_func(_io, _error);           \
	} while(0)


#endif /* __OCF_IO_PRIV_H__ */
