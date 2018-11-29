/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_DATA_OBJ_PRIV_H__
#define __OCF_DATA_OBJ_PRIV_H__

#include "ocf_env.h"
#include "ocf_io_priv.h"

struct ocf_data_obj_type {
	const struct ocf_data_obj_properties *properties;
	env_allocator *allocator;
};

struct ocf_data_obj {
	ocf_data_obj_type_t type;
	struct ocf_data_obj_uuid uuid;
	bool uuid_copy;
	void *priv;
	ocf_cache_t cache;
	struct list_head core_pool_item;
	struct {
		unsigned discard_zeroes:1;
			/* true if reading discarded pages returns 0 */
	} features;
};

int ocf_data_obj_type_init(struct ocf_data_obj_type **type,
		const struct ocf_data_obj_properties *properties);

void ocf_data_obj_type_deinit(struct ocf_data_obj_type *type);

static inline struct ocf_io *ocf_dobj_new_io(ocf_data_obj_t obj)
{
	ENV_BUG_ON(!obj->type->properties->ops.new_io);

	return obj->type->properties->ops.new_io(obj);
}

static inline void ocf_dobj_submit_io(struct ocf_io *io)
{
	ENV_BUG_ON(!io->obj->type->properties->ops.submit_io);

	io->obj->type->properties->ops.submit_io(io);
}

static inline void ocf_dobj_submit_flush(struct ocf_io *io)
{
	ENV_BUG_ON(!io->obj->type->properties->ops.submit_flush);
	/*
	 * TODO(rbaldyga): Maybe we should supply function for checking
	 * submit_flush availability and return -ENOTSUPP here?
	 */
	if (!io->obj->type->properties->ops.submit_flush)
		ocf_io_end(io, 0);
	else
		io->obj->type->properties->ops.submit_flush(io);
}

static inline void ocf_dobj_submit_discard(struct ocf_io *io)
{
	ENV_BUG_ON(!io->obj->type->properties->ops.submit_discard);
	/*
	 * TODO(rbaldyga): Maybe we should supply function for checking
	 * submit_discard availability and return -ENOTSUPP here?
	 */
	if (!io->obj->type->properties->ops.submit_discard)
		ocf_io_end(io, 0);
	else
		io->obj->type->properties->ops.submit_discard(io);
}

static inline void ocf_dobj_submit_metadata(struct ocf_io *io)
{
	ENV_BUG_ON(!io->obj->type->properties->ops.submit_metadata);

	io->obj->type->properties->ops.submit_metadata(io);
}

static inline void ocf_dobj_submit_write_zeroes(struct ocf_io *io)
{
	ENV_BUG_ON(!io->obj->type->properties->ops.submit_write_zeroes);

	io->obj->type->properties->ops.submit_write_zeroes(io);
}

static inline int ocf_data_obj_open(ocf_data_obj_t obj)
{
	ENV_BUG_ON(!obj->type->properties->ops.open);

	return obj->type->properties->ops.open(obj);
}

static inline void ocf_data_obj_close(ocf_data_obj_t obj)
{
	ENV_BUG_ON(!obj->type->properties->ops.close);

	obj->type->properties->ops.close(obj);
}

static inline unsigned int ocf_data_obj_get_max_io_size(ocf_data_obj_t obj)
{
	ENV_BUG_ON(!obj->type->properties->ops.get_max_io_size);

	return obj->type->properties->ops.get_max_io_size(obj);
}

static inline int ocf_data_obj_is_atomic(ocf_data_obj_t obj)
{
	return obj->type->properties->caps.atomic_writes;
}

#endif  /*__OCF_DATA_OBJ_PRIV_H__ */
