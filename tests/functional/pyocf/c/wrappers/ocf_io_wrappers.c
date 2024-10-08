/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf_io.h"
#include "ocf/ocf_core.h"

void ocf_io_set_cmpl_wrapper(ocf_io_t io, void *context,
		void *context2, ocf_end_io_t fn)
{
	ocf_io_set_cmpl(io, context, context2, fn);
}

void ocf_io_set_start_wrapper(ocf_io_t io, ocf_start_io_t fn)
{
	ocf_io_set_start(io, fn);
}

void ocf_io_set_handle_wrapper(ocf_io_t io, ocf_handle_io_t fn)
{
	ocf_io_set_handle(io, fn);
}

void ocf_core_submit_io_wrapper(ocf_io_t io)
{
	ocf_core_submit_io(io);
}


void ocf_core_submit_flush_wrapper(ocf_io_t io)
{
	ocf_core_submit_flush(io);
}

void ocf_core_submit_discard_wrapper(ocf_io_t io)
{
	ocf_core_submit_discard(io);
}
