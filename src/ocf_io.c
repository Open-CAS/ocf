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

#define OCF_IO_TOTAL_SIZE(priv_size) (sizeof(struct ocf_io_meta) + \
		sizeof(struct ocf_io) + priv_size)

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

void *ocf_io_get_meta(struct ocf_io* io)
{
	return (void *)io - sizeof(struct ocf_io_meta);
}

struct ocf_io *ocf_io_new(ocf_volume_t volume)
{
	struct ocf_io *io;
	struct ocf_io_meta *io_meta;
	void *data;

	if (!ocf_refcnt_inc(&volume->refcnt))
		return NULL;

	data = env_allocator_new(volume->type->allocator);
	if (!data) {
		ocf_refcnt_dec(&volume->refcnt);
		return NULL;
	}

	io = data + sizeof(struct ocf_io_meta);

	io_meta = ocf_io_get_meta(io);

	io->volume = volume;
	io->ops = &volume->type->properties->io_ops;
	env_atomic_set(&io_meta->ref_count, 1);

	return io;
}

/*
 * IO external API
 */

void *ocf_io_get_priv(struct ocf_io* io)
{
	return (void *)io + sizeof(struct ocf_io);
}

void ocf_io_get(struct ocf_io *io)
{
	struct ocf_io_meta *io_meta = ocf_io_get_meta(io);

	env_atomic_inc_return(&io_meta->ref_count);
}

void ocf_io_put(struct ocf_io *io)
{
	struct ocf_io_meta *io_meta = ocf_io_get_meta(io);

	if (env_atomic_dec_return(&io_meta->ref_count))
		return;

	ocf_refcnt_dec(&io->volume->refcnt);

	env_allocator_del(io->volume->type->allocator,
			(void *)io - sizeof(struct ocf_io_meta));
}
