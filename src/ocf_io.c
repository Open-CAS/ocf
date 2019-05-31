/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_io_priv.h"
#include "ocf_volume_priv.h"

/*
 * This is io allocator dedicated for bottom devices.
 * Out IO structure looks like this:
 * --------------> +-------------------------+
 * | OCF is aware  |                         |
 * | of this part. | struct ocf_io_meta      |
 * |               |                         |
 * |               +-------------------------+ <----------------
 * |               |                         |  Bottom adapter |
 * |               | struct ocf_io           |  is aware of    |
 * |               |                         |  this part.     |
 * --------------> +-------------------------+                 |
 *                 |                         |                 |
 *                 | Bottom adapter specific |                 |
 *                 | context data structure. |                 |
 *                 |                         |                 |
 *                 +-------------------------+ <----------------
 */

#define OCF_IO_TOTAL_SIZE(priv_size) \
		(sizeof(struct ocf_io_internal) + priv_size)

env_allocator *ocf_io_allocator_create(uint32_t size, const char *name)
{
	return env_allocator_create(OCF_IO_TOTAL_SIZE(size), name);
}

void ocf_io_allocator_destroy(env_allocator *allocator)
{
	env_allocator_destroy(allocator);
}

/*
 * IO internal API
 */

static struct ocf_io_internal *ocf_io_get_internal(struct ocf_io* io)
{
	return container_of(io, struct ocf_io_internal, io);
}

struct ocf_io *ocf_io_new(ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir,
		uint32_t io_class, uint64_t flags)
{
	struct ocf_io_internal *ioi;

	if (!ocf_refcnt_inc(&volume->refcnt))
		return NULL;

	ioi = env_allocator_new(volume->type->allocator);
	if (!ioi) {
		ocf_refcnt_dec(&volume->refcnt);
		return NULL;
	}

	ioi->meta.volume = volume;
	ioi->meta.ops = &volume->type->properties->io_ops;
	env_atomic_set(&ioi->meta.ref_count, 1);

	ioi->io.io_queue = queue;
	ioi->io.addr = addr;
	ioi->io.bytes = bytes;
	ioi->io.dir = dir;
	ioi->io.io_class = io_class;
	ioi->io.flags = flags;

	return &ioi->io;
}

/*
 * IO external API
 */

void *ocf_io_get_priv(struct ocf_io* io)
{
	return (void *)io + sizeof(struct ocf_io);
}

int ocf_io_set_data(struct ocf_io *io, ctx_data_t *data, uint32_t offset)
{
	struct ocf_io_internal *ioi = ocf_io_get_internal(io);

	return ioi->meta.ops->set_data(io, data, offset);
}

ctx_data_t *ocf_io_get_data(struct ocf_io *io)
{
	struct ocf_io_internal *ioi = ocf_io_get_internal(io);

	return ioi->meta.ops->get_data(io);
}

void ocf_io_get(struct ocf_io *io)
{
	struct ocf_io_internal *ioi = ocf_io_get_internal(io);

	env_atomic_inc_return(&ioi->meta.ref_count);
}

void ocf_io_put(struct ocf_io *io)
{
	struct ocf_io_internal *ioi = ocf_io_get_internal(io);

	if (env_atomic_dec_return(&ioi->meta.ref_count))
		return;

	ocf_refcnt_dec(&ioi->meta.volume->refcnt);

	env_allocator_del(ioi->meta.volume->type->allocator, (void *)ioi);
}

ocf_volume_t ocf_io_get_volume(struct ocf_io *io)
{
	struct ocf_io_internal *ioi = ocf_io_get_internal(io);

	return ioi->meta.volume;
}
