/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <ocf/ocf.h>
#include "dobj.h"
#include "data.h"
#include "ctx.h"

#define DOBJ_SIZE 200*1024*1024

/*
 * In open() function we store uuid data as object name (for debug messages)
 * and allocate 200 MiB of memory to simulate backend storage device.
 */
static int dobj_open(ocf_data_obj_t obj)
{
	const struct ocf_data_obj_uuid *uuid = ocf_dobj_get_uuid(obj);
	struct dobj *dobj = ocf_dobj_get_priv(obj);

	dobj->name = ocf_uuid_to_str(uuid);
	dobj->mem = malloc(DOBJ_SIZE);

	printf("DOBJ OPEN: (name: %s)\n", dobj->name);

	return 0;
}

/*
 * In close() function we just free memory allocated in open().
 */
static void dobj_close(ocf_data_obj_t obj)
{
	struct dobj *dobj = ocf_dobj_get_priv(obj);

	printf("DOBJ CLOSE: (name: %s)\n", dobj->name);
	free(dobj->mem);
}

/*
 * In submit_io() function we simulate read or write to backend storage device
 * by doing memcpy() to or from previously allocated memory buffer.
 */
static void dobj_submit_io(struct ocf_io *io)
{
	struct dobj_data *data;
	struct dobj *dobj;

	data = ocf_io_get_data(io);
	dobj = ocf_dobj_get_priv(io->obj);

	if (io->dir == OCF_WRITE) {
		memcpy(dobj->mem + io->addr,
				data->ptr + data->offset, io->bytes);
	} else {
		memcpy(data->ptr + data->offset,
				dobj->mem + io->addr, io->bytes);
	}

	printf("DOBJ: (name: %s), IO: (dir: %s, addr: %ld, bytes: %d)\n",
			dobj->name, io->dir == OCF_READ ? "read" : "write",
			io->addr, io->bytes);

	io->end(io, 0);
}

/*
 * We don't need to implement submit_flush(). Just complete io with success.
 */
static void dobj_submit_flush(struct ocf_io *io)
{
	io->end(io, 0);
}

/*
 * We don't need to implement submit_discard(). Just complete io with success.
 */
static void dobj_submit_discard(struct ocf_io *io)
{
	io->end(io, 0);
}

/*
 * Let's set maximum io size to 128 KiB.
 */
static unsigned int dobj_get_max_io_size(ocf_data_obj_t obj)
{
	return 128 * 1024;
}

/*
 * Return data object size.
 */
static uint64_t dobj_get_length(ocf_data_obj_t obj)
{
	return DOBJ_SIZE;
}

/*
 * In set_data() we just assing data and offset to io.
 */
static int dobj_io_set_data(struct ocf_io *io, ctx_data_t *data,
		uint32_t offset)
{
	struct dobj_io *dobj_io = ocf_io_get_priv(io);

	dobj_io->data = data;
	dobj_io->offset = offset;

	return 0;
}

/*
 * In get_data() return data stored in io.
 */
static ctx_data_t *dobj_io_get_data(struct ocf_io *io)
{
	struct dobj_io *dobj_io = ocf_io_get_priv(io);

	return dobj_io->data;
}

/*
 * This structure contains data object properties. It describes data object
 * type, which can be later instantiated as backend storage object for cache
 * or core.
 */
const struct ocf_data_obj_properties dobj_properties = {
	.name = "Example dobj",
	.io_priv_size = sizeof(struct dobj_io),
	.dobj_priv_size = sizeof(struct dobj),
	.caps = {
		.atomic_writes = 0,
	},
	.ops = {
		.open = dobj_open,
		.close = dobj_close,
		.submit_io = dobj_submit_io,
		.submit_flush = dobj_submit_flush,
		.submit_discard = dobj_submit_discard,
		.get_max_io_size = dobj_get_max_io_size,
		.get_length = dobj_get_length,
	},
	.io_ops = {
		.set_data = dobj_io_set_data,
		.get_data = dobj_io_get_data,
	},
};

/*
 * This function registers data object type in OCF context.
 * It should be called just after context initialization.
 */
int dobj_init(ocf_ctx_t ocf_ctx)
{
	return ocf_ctx_register_data_obj_type(ocf_ctx, OBJ_TYPE,
			&dobj_properties);
}

/*
 * This function unregisters data object type in OCF context.
 * It should be called just before context cleanup.
 */
void dobj_cleanup(ocf_ctx_t ocf_ctx)
{
	ocf_ctx_unregister_data_obj_type(ocf_ctx, OBJ_TYPE);
}
