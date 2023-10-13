/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_IO_PRIV_H__
#define __OCF_IO_PRIV_H__

#include "ocf/ocf.h"
#include "utils/utils_io_allocator.h"

struct ocf_io_meta {
	ocf_volume_t volume;
	env_atomic ref_count;
	struct ocf_request *req;
};

struct ocf_io_internal {
	struct ocf_io_meta meta;
	struct ocf_io io;
};

int ocf_io_allocator_default_init(ocf_io_allocator_t allocator,
		const char *name);

void ocf_io_allocator_default_deinit(ocf_io_allocator_t allocator);

void *ocf_io_allocator_default_new(ocf_io_allocator_t allocator,
		ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir);

void ocf_io_allocator_default_del(ocf_io_allocator_t allocator, void *obj);

struct ocf_io *ocf_io_new(ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir,
		uint32_t io_class, uint64_t flags);


static inline void ocf_io_end(struct ocf_io *io, int error)
{
	if (io->end)
		io->end(io, error);

}

#endif /* __OCF_IO_PRIV_H__ */
