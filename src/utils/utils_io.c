/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../ocf_priv.h"
#include "../ocf_cache_priv.h"
#include "../ocf_volume_priv.h"
#include "../ocf_request.h"
#include "utils_io.h"
#include "utils_cache_line.h"

struct ocf_submit_volume_context {
	env_atomic req_remaining;
	int error;
	ocf_submit_end_t cmpl;
	void *priv;
};

static void _ocf_volume_flush_end(struct ocf_io *io, int error)
{
	ocf_submit_end_t cmpl = io->priv1;

	cmpl(io->priv2, error);
	ocf_io_put(io);
}

void ocf_submit_volume_flush(ocf_volume_t volume,
		ocf_submit_end_t cmpl, void *priv)
{
	struct ocf_io *io;

	io = ocf_volume_new_io(volume, NULL, 0, 0, OCF_WRITE, 0, 0);
	if (!io)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	ocf_io_set_cmpl(io, cmpl, priv, _ocf_volume_flush_end);

	ocf_volume_submit_flush(io);
}

static void ocf_submit_volume_end(struct ocf_io *io, int error)
{
	struct ocf_submit_volume_context *context = io->priv1;

	if (error)
		context->error = error;

	ocf_io_put(io);

	if (env_atomic_dec_return(&context->req_remaining))
		return;

	context->cmpl(context->priv, context->error);
	env_vfree(context);
}

void ocf_submit_volume_discard(ocf_volume_t volume, uint64_t addr,
		uint64_t length, ocf_submit_end_t cmpl, void *priv)
{
	struct ocf_submit_volume_context *context;
	uint64_t bytes;
	uint64_t sector_mask = (1 << ENV_SECTOR_SHIFT) - 1;
	uint64_t max_length = (uint32_t)~0 & ~sector_mask;
	struct ocf_io *io;

	context = env_vzalloc(sizeof(*context));
	if (!context)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	env_atomic_set(&context->req_remaining, 1);
	context->cmpl = cmpl;
	context->priv = priv;

	while (length) {
		bytes = OCF_MIN(length, max_length);

		io = ocf_volume_new_io(volume, NULL, addr, bytes,
				OCF_WRITE, 0, 0);
		if (!io) {
			context->error = -OCF_ERR_NO_MEM;
			break;
		}

		env_atomic_inc(&context->req_remaining);

		ocf_io_set_cmpl(io, context, NULL, ocf_submit_volume_end);
		ocf_volume_submit_discard(io);

		addr += bytes;
		length -= bytes;
	}

	if (env_atomic_dec_return(&context->req_remaining))
		return;

	cmpl(priv, context->error);
	env_vfree(context);
}

void ocf_submit_write_zeros(ocf_volume_t volume, uint64_t addr,
		uint64_t length, ocf_submit_end_t cmpl, void *priv)
{
	struct ocf_submit_volume_context *context;
	uint32_t bytes;
	uint32_t max_length = ~((uint32_t)PAGE_SIZE - 1);
	struct ocf_io *io;

	context = env_vzalloc(sizeof(*context));
	if (!context)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	env_atomic_set(&context->req_remaining, 1);
	context->cmpl = cmpl;
	context->priv = priv;

	while (length) {
		bytes = OCF_MIN(length, max_length);

		io = ocf_volume_new_io(volume, NULL, addr, bytes,
				OCF_WRITE, 0, 0);
		if (!io) {
			context->error = -OCF_ERR_NO_MEM;
			break;
		}

		env_atomic_inc(&context->req_remaining);

		ocf_io_set_cmpl(io, context, NULL, ocf_submit_volume_end);
		ocf_volume_submit_write_zeroes(io);

		addr += bytes;
		length -= bytes;
	}

	if (env_atomic_dec_return(&context->req_remaining))
		return;

	cmpl(priv, context->error);
	env_vfree(context);
}

struct ocf_submit_cache_page_context {
	ocf_cache_t cache;
	void *buffer;
	ocf_submit_end_t cmpl;
	void *priv;
};

static void ocf_submit_cache_page_end(struct ocf_io *io, int error)
{
	struct ocf_submit_cache_page_context *context = io->priv1;
	ctx_data_t *data = ocf_io_get_data(io);

	if (io->dir == OCF_READ) {
		ctx_data_rd_check(context->cache->owner, context->buffer,
				data, PAGE_SIZE);
	}

	context->cmpl(context->priv, error);
	ctx_data_free(context->cache->owner, data);
	env_vfree(context);
	ocf_io_put(io);
}

void ocf_submit_cache_page(ocf_cache_t cache, uint64_t addr, int dir,
		void *buffer, ocf_submit_end_t cmpl, void *priv)
{
	struct ocf_submit_cache_page_context *context;
	ctx_data_t *data;
	struct ocf_io *io;
	int result = 0;

	context = env_vmalloc(sizeof(*context));
	if (!context)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	context->cache = cache;
	context->buffer = buffer;
	context->cmpl = cmpl;
	context->priv = priv;

	io = ocf_new_cache_io(cache, NULL, addr, PAGE_SIZE, dir, 0, 0);
	if (!io) {
		result = -OCF_ERR_NO_MEM;
		goto err_io;
	}

	data = ctx_data_alloc(cache->owner, 1);
	if (!data) {
		result = -OCF_ERR_NO_MEM;
		goto err_data;
	}

	if (dir == OCF_WRITE)
		ctx_data_wr_check(cache->owner, data, buffer, PAGE_SIZE);

	result = ocf_io_set_data(io, data, 0);
	if (result)
		goto err_set_data;

	ocf_io_set_cmpl(io, context, NULL, ocf_submit_cache_page_end);

	ocf_volume_submit_io(io);
	return;

err_set_data:
	ctx_data_free(cache->owner, data);
err_data:
	ocf_io_put(io);
err_io:
	env_vfree(context);
	cmpl(priv, result);
}
