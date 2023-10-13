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
	return env_allocator_new(allocator->priv);
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

struct ocf_io *ocf_io_new(ocf_volume_t volume, ocf_queue_t queue,
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

	req->ioi.meta.volume = volume;
	env_atomic_set(&req->ioi.meta.ref_count, 1);

	req->ioi.io.io_queue = queue;
	req->ioi.io.addr = addr;
	req->ioi.io.bytes = bytes;
	req->ioi.io.dir = dir;
	req->ioi.io.io_class = io_class;
	req->ioi.io.flags = flags;

	return &req->ioi.io;
}

/*
 * IO external API
 */

int ocf_io_set_data(struct ocf_io *io, ctx_data_t *data, uint32_t offset)
{
	struct ocf_request *req = ocf_io_to_req(io);

	req->data = data;
	req->offset = offset;

	return 0;
}

ctx_data_t *ocf_io_get_data(struct ocf_io *io)
{
	struct ocf_request *req = ocf_io_to_req(io);

	return req->data;
}

uint32_t ocf_io_get_offset(struct ocf_io *io)
{
	struct ocf_request *req = ocf_io_to_req(io);

	return req->offset;
}

void ocf_io_get(struct ocf_io *io)
{
	struct ocf_request *req = ocf_io_to_req(io);

	env_atomic_inc_return(&req->ioi.meta.ref_count);
}

void ocf_io_put(struct ocf_io *io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	struct ocf_volume *volume;

	if (env_atomic_dec_return(&req->ioi.meta.ref_count))
		return;

	/* Hold volume reference to avoid use after free of req */
	volume = req->ioi.meta.volume;

	ocf_io_allocator_del(&volume->type->allocator, (void *)req);

	ocf_refcnt_dec(&volume->refcnt);
}

ocf_volume_t ocf_io_get_volume(struct ocf_io *io)
{
	struct ocf_request *req = ocf_io_to_req(io);

	return req->ioi.meta.volume;
}
