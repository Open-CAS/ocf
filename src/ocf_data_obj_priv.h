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

#endif  /*__OCF_DATA_OBJ_PRIV_H__ */
