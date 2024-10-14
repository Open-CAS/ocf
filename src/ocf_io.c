/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_def_priv.h"
#include "ocf_io_priv.h"
#include "ocf_volume_priv.h"
#include "ocf_core_priv.h"
#include "utils/utils_io_allocator.h"

int ocf_io_allocator_default_init(ocf_io_allocator_t allocator,
		const char *name)
{
	allocator->priv = env_allocator_create(sizeof(struct ocf_request), name,
			true);
	if (!allocator->priv)
		return -OCF_ERR_NO_MEM;

	return 0;
}

void ocf_io_allocator_default_deinit(ocf_io_allocator_t allocator)
{
	env_allocator_destroy(allocator->priv);
	allocator->priv = NULL;
}

void *ocf_io_allocator_default_new(ocf_io_allocator_t allocator,
		ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir)
{
	struct ocf_request *req;

	req = env_allocator_new(allocator->priv);
	if (!req)
		return NULL;

	req->io_queue = queue;
	req->addr = addr;
	req->bytes = bytes;
	req->rw = dir;

	return req;
}

void ocf_io_allocator_default_del(ocf_io_allocator_t allocator, void *obj)
{
	env_allocator_del(allocator->priv, obj);
}

const struct ocf_io_allocator_type type_default = {
	.ops = {
		.allocator_init = ocf_io_allocator_default_init,
		.allocator_deinit = ocf_io_allocator_default_deinit,
		.allocator_new = ocf_io_allocator_default_new,
		.allocator_del = ocf_io_allocator_default_del,
	},
};

ocf_io_allocator_type_t ocf_io_allocator_get_type_default(void)
{
	return &type_default;
}

/*
 * IO internal API
 */

ocf_io_t ocf_io_new(ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir,
		uint32_t io_class, uint64_t flags)
{
	struct ocf_request *req;
	uint32_t sector_size = SECTORS_TO_BYTES(1);

	if ((addr % sector_size) || (bytes % sector_size))
		return NULL;

	if (!ocf_refcnt_inc(&volume->refcnt))
		return NULL;

	req = ocf_io_allocator_new(&volume->type->allocator, volume, queue,
			addr, bytes, dir);
	if (!req) {
		ocf_refcnt_dec(&volume->refcnt);
		return NULL;
	}

	env_atomic_set(&req->io.ref_count, 1);
	req->io.volume = volume;
	req->io.io_class = io_class;
	req->flags = flags;

	return req;
}

/*
 * IO external API
 */

int ocf_io_set_data(ocf_io_t io, ctx_data_t *data, uint32_t offset)
{
	struct ocf_request *req = ocf_io_to_req(io);

	req->data = data;
	req->offset = offset;

	return 0;
}

ctx_data_t *ocf_io_get_data(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);

	return req->data;
}

uint32_t ocf_io_get_offset(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);

	return req->offset;
}

void ocf_io_put(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	struct ocf_volume *volume;

	if (env_atomic_dec_return(&req->io.ref_count))
		return;

	volume = req->io.volume;

	ocf_io_allocator_del(&volume->type->allocator, (void *)req);

	ocf_refcnt_dec(&volume->refcnt);
}

ocf_volume_t ocf_io_get_volume(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);

	return req->io.volume;
}

void ocf_io_set_cmpl(ocf_io_t io, void *context,
		void *context2, ocf_end_io_t fn)
{
	struct ocf_request *req = ocf_io_to_req(io);

	req->io.priv1 = context;
	req->io.priv2 = context2;
	req->io.end = fn;
}

void ocf_io_set_start(ocf_io_t io, ocf_start_io_t fn)
{
	struct ocf_request *req = ocf_io_to_req(io);

	req->io.start = fn;
}

void ocf_io_set_handle(ocf_io_t io, ocf_handle_io_t fn)
{
	struct ocf_request *req = ocf_io_to_req(io);

	req->io.handle = fn;
}
