/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_IO_RESOURCE_H__
#define __METADATA_IO_RESOURCE_H__

/*
 * ocf_ctx resource
 */
struct ocf_metadata_io_resource {
	struct env_mpool *mpool;
	int ref_count;
};

/**
 * Initialize ocf_ctx related structures of metadata_io.
 */
int ocf_metadata_io_ctx_init(struct ocf_ctx *ocf_ctx);

/**
 * Deinitialize ocf_ctx related structures of metadata_io
 */
void ocf_metadata_io_ctx_deinit(struct ocf_ctx *ocf_ctx);

/**
 * Initialize per-ocf_ctx mio resources
 *
 * Can be safely called multiple times - refcount based.
 */
int ocf_metadata_io_open(struct ocf_ctx *ocf_ctx);

/**
 * Decrements the refcount of per-ocf_ctx mio resources
 *
 * Needs to be called as many times as ocf_metadata_io_open().
 */
void ocf_metadata_io_close(struct ocf_ctx *ocf_ctx);

#endif /* __METADATA_IO_RESOURCE_H__ */
