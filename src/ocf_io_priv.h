/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_IO_PRIV_H__
#define __OCF_IO_PRIV_H__

#include "ocf_request.h"

struct ocf_io_meta {
	struct ocf_request *req;
};

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
