/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_METADATA_PASSIVE_IO_H__
#define __OCF_METADATA_PASSIVE_IO_H__

int ocf_metadata_passive_update(ocf_cache_t cache, struct ocf_io *io,
		ocf_end_io_t io_cmpl);

int ocf_metadata_passive_io_ctx_init(ocf_cache_t cache);

void ocf_metadata_passive_io_ctx_deinit(ocf_cache_t cache);

#endif
