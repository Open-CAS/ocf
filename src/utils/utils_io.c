/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../ocf_priv.h"
#include "../ocf_cache_priv.h"
#include "../ocf_volume_priv.h"
#include "../ocf_request.h"
#include "ocf/ocf_blktrace.h"
#include "utils_io.h"
#include "utils_cache_line.h"

struct ocf_submit_cache_context {
	ocf_submit_end_t cmpl;
	void *priv;
};

static void ocf_submit_cache_end(struct ocf_request *req, int error)
{
	struct ocf_submit_cache_context *context = req->priv;

	context->cmpl(context->priv, error);
	env_vfree(context);
	ocf_req_put(req);
}

void ocf_submit_cache_flush(ocf_cache_t cache,
		ocf_submit_end_t cmpl, void *priv)
{
	struct ocf_submit_cache_context *context;
	struct ocf_request *req;

	context = env_vzalloc(sizeof(*context));
	if (!context)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	context->cmpl = cmpl;
	context->priv = priv;

	req = ocf_req_new_mngt(cache, cache->mngt_queue);
	if (!req) {
		cmpl(priv, -OCF_ERR_NO_MEM);
		env_vfree(context);
		return;
	}

	req->cache_forward_end = ocf_submit_cache_end;
	req->priv = context;

	ocf_req_forward_cache_flush(req);
}

void ocf_submit_cache_discard(ocf_cache_t cache, uint64_t addr,
		uint64_t length, ocf_submit_end_t cmpl, void *priv)
{
	struct ocf_submit_cache_context *context;
	uint64_t bytes;
	uint64_t sector_mask = (1 << ENV_SECTOR_SHIFT) - 1;
	uint64_t max_length = (uint32_t)~0 & ~sector_mask;
	struct ocf_request *req;

	context = env_vzalloc(sizeof(*context));
	if (!context)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	context->cmpl = cmpl;
	context->priv = priv;

	req = ocf_req_new_mngt(cache, cache->mngt_queue);
	if (!req) {
		cmpl(priv, -OCF_ERR_NO_MEM);
		env_vfree(context);
		return;
	}

	req->cache_forward_end = ocf_submit_cache_end;
	req->priv = context;

	ocf_req_forward_cache_get(req);
	while (length) {
		bytes = OCF_MIN(length, max_length);

		ocf_req_forward_cache_discard(req, addr, bytes);

		addr += bytes;
		length -= bytes;
	}
	ocf_req_forward_cache_put(req);
}

void ocf_submit_cache_write_zeros(ocf_cache_t cache, uint64_t addr,
		uint64_t length, ocf_submit_end_t cmpl, void *priv)
{
	struct ocf_submit_cache_context *context;
	uint32_t bytes;
	uint32_t max_length = ~((uint32_t)PAGE_SIZE - 1);
	struct ocf_request *req;

	context = env_vzalloc(sizeof(*context));
	if (!context)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	context->cmpl = cmpl;
	context->priv = priv;

	req = ocf_req_new_mngt(cache, cache->mngt_queue);
	if (!req) {
		cmpl(priv, -OCF_ERR_NO_MEM);
		env_vfree(context);
		return;
	}

	ocf_req_forward_cache_get(req);
	while (length) {
		bytes = OCF_MIN(length, max_length);

		ocf_req_forward_cache_write_zeros(req, addr, bytes);

		addr += bytes;
		length -= bytes;
	}
	ocf_req_forward_cache_put(req);
}

struct ocf_submit_cache_page_context {
	ocf_cache_t cache;
	void *buffer;
	ocf_submit_end_t cmpl;
	void *priv;
};

static void ocf_submit_cache_page_end(struct ocf_request *req, int error)
{
	struct ocf_submit_cache_page_context *context = req->priv;
	ctx_data_t *data = req->data;

	if (req->rw == OCF_READ) {
		ctx_data_rd_check(context->cache->owner, context->buffer,
				data, PAGE_SIZE);
	}

	context->cmpl(context->priv, error);
	ctx_data_free(context->cache->owner, data);
	env_vfree(context);
	ocf_req_put(req);
}

void ocf_submit_cache_page(ocf_cache_t cache, uint64_t addr, int dir,
		void *buffer, ocf_submit_end_t cmpl, void *priv)
{
	struct ocf_submit_cache_page_context *context;
	ctx_data_t *data;
	struct ocf_request *req;
	int result = 0;

	context = env_vmalloc(sizeof(*context));
	if (!context)
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);

	context->cache = cache;
	context->buffer = buffer;
	context->cmpl = cmpl;
	context->priv = priv;

	req = ocf_req_new_mngt(cache, cache->mngt_queue);
	if (!req) {
		result = -OCF_ERR_NO_MEM;
		goto err_req;
	}

	data = ctx_data_alloc(cache->owner, 1);
	if (!data) {
		result = -OCF_ERR_NO_MEM;
		goto err_data;
	}

	if (dir == OCF_WRITE)
		ctx_data_wr_check(cache->owner, data, buffer, PAGE_SIZE);

	req->data = data;

	req->cache_forward_end = ocf_submit_cache_page_end;
	req->priv = context;
	req->rw = dir;
	req->addr = addr;
	req->bytes = PAGE_SIZE;

	ocf_req_forward_cache_io(req, dir, addr, PAGE_SIZE, 0);
	return;

err_data:
	ocf_req_put(req);
err_req:
	env_vfree(context);
	cmpl(priv, result);
}
