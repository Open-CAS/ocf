/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_IO_PRIV_H__
#define __OCF_IO_PRIV_H__

#include "ocf/ocf.h"
#include "ocf_request.h"

struct ocf_io_meta {
	env_atomic ref_count;
	struct ocf_request *req;
};

env_allocator *ocf_io_allocator_create(uint32_t size, const char *name);

void ocf_io_allocator_destroy(env_allocator *allocator);

struct ocf_io *ocf_io_new(ocf_data_obj_t obj);

static inline void ocf_io_start(struct ocf_io *io)
{
	/*
	 * We want to call start() callback only once, so after calling
	 * we set it to NULL to prevent multiple calls.
	 */
	if (io->start) {
		io->start(io);
		io->start = NULL;
	}
}

static inline void ocf_io_end(struct ocf_io *io, int error)
{
	if (io->end)
		io->end(io, error);

}

#endif /* __OCF_IO_PRIV_H__ */
