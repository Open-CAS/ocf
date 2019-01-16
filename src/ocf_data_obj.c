/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_priv.h"
#include "ocf_data_obj_priv.h"
#include "ocf_io_priv.h"
#include "ocf_env.h"

/* *** Bottom interface *** */

/*
 * Data object type
 */

int ocf_data_obj_type_init(struct ocf_data_obj_type **type,
		const struct ocf_data_obj_properties *properties)
{
	const struct ocf_data_obj_ops *ops = &properties->ops;
	struct ocf_data_obj_type *new_type;
	int ret;

	if (!ops->submit_io || !ops->open || !ops->close ||
			!ops->get_max_io_size || !ops->get_length) {
		return -EINVAL;
	}

	if (properties->caps.atomic_writes && !ops->submit_metadata)
		return -EINVAL;

	new_type = env_zalloc(sizeof(**type), ENV_MEM_NORMAL);
	if (!new_type)
		return -OCF_ERR_NO_MEM;

	new_type->allocator = ocf_io_allocator_create(
			properties->io_priv_size, properties->name);
	if (!new_type->allocator) {
		ret = -ENOMEM;
		goto err;
	}

	new_type->properties = properties;

	*type = new_type;

	return 0;

err:
	env_free(new_type);
	return ret;
}

void ocf_data_obj_type_deinit(struct ocf_data_obj_type *type)
{
	ocf_io_allocator_destroy(type->allocator);
	env_free(type);
}

/*
 * Data object frontend API
 */

int ocf_dobj_init(ocf_data_obj_t obj, ocf_data_obj_type_t type,
		struct ocf_data_obj_uuid *uuid, bool uuid_copy)
{
	uint32_t priv_size = type->properties->dobj_priv_size;
	void *data;
	int ret;

	if (!obj || !type)
		return -OCF_ERR_INVAL;

	obj->opened = false;
	obj->type = type;

	obj->priv = env_zalloc(priv_size, ENV_MEM_NORMAL);
	if (!obj->priv)
		return -OCF_ERR_NO_MEM;

	if (!uuid) {
		obj->uuid.size = 0;
		obj->uuid.data = NULL;
		obj->uuid_copy = false;
		return 0;
	}

	obj->uuid_copy = uuid_copy;

	if (uuid_copy) {
		data = env_vmalloc(uuid->size);
		if (!data)
			goto err;

		ret = env_memcpy(data, uuid->size, uuid->data, uuid->size);
		if (ret) {
			env_vfree(data);
			goto err;
		}

		obj->uuid.data = data;
	} else {
		obj->uuid.data = uuid->data;
	}

	obj->uuid.size = uuid->size;

	return 0;

err:
	env_free(obj->priv);
	return -OCF_ERR_NO_MEM;
}

void ocf_dobj_deinit(ocf_data_obj_t obj)
{
	OCF_CHECK_NULL(obj);

	env_free(obj->priv);

	if (obj->uuid_copy && obj->uuid.data)
		env_vfree(obj->uuid.data);
}

void ocf_dobj_move(ocf_data_obj_t obj, ocf_data_obj_t from)
{
	OCF_CHECK_NULL(obj);
	OCF_CHECK_NULL(from);

	ocf_dobj_deinit(obj);

	obj->opened = from->opened;
	obj->type = from->type;
	obj->uuid = from->uuid;
	obj->uuid_copy = from->uuid_copy;
	obj->priv = from->priv;
	obj->cache = from->cache;
	obj->features = from->features;

	/*
	 * Deinitialize original object without freeing resources.
	 */
	from->opened = false;
	from->priv = NULL;
}

int ocf_dobj_create(ocf_data_obj_t *obj, ocf_data_obj_type_t type,
		struct ocf_data_obj_uuid *uuid)
{
	ocf_data_obj_t tmp_obj;
	int ret;

	OCF_CHECK_NULL(obj);

	tmp_obj = env_zalloc(sizeof(*tmp_obj), ENV_MEM_NORMAL);
	if (!tmp_obj)
		return -OCF_ERR_NO_MEM;

	ret = ocf_dobj_init(tmp_obj, type, uuid, true);
	if (ret) {
		env_free(tmp_obj);
		return ret;
	}

	*obj = tmp_obj;

	return 0;
}

void ocf_dobj_destroy(ocf_data_obj_t obj)
{
	OCF_CHECK_NULL(obj);

	ocf_dobj_deinit(obj);
	env_free(obj);
}

ocf_data_obj_type_t ocf_dobj_get_type(ocf_data_obj_t obj)
{
	OCF_CHECK_NULL(obj);

	return obj->type;
}

const struct ocf_data_obj_uuid *ocf_dobj_get_uuid(ocf_data_obj_t obj)
{
	OCF_CHECK_NULL(obj);

	return &obj->uuid;
}

void ocf_dobj_set_uuid(ocf_data_obj_t obj, const struct ocf_data_obj_uuid *uuid)
{
	OCF_CHECK_NULL(obj);

	if (obj->uuid_copy && obj->uuid.data)
		env_vfree(obj->uuid.data);

	obj->uuid.data = uuid->data;
	obj->uuid.size = uuid->size;
}

void *ocf_dobj_get_priv(ocf_data_obj_t obj)
{
	return obj->priv;
}

ocf_cache_t ocf_dobj_get_cache(ocf_data_obj_t obj)
{
	OCF_CHECK_NULL(obj);

	return obj->cache;
}

int ocf_dobj_is_atomic(ocf_data_obj_t obj)
{
	return obj->type->properties->caps.atomic_writes;
}

struct ocf_io *ocf_dobj_new_io(ocf_data_obj_t obj)
{
	if (!obj->opened)
		return NULL;

	return ocf_io_new(obj);
}

void ocf_dobj_submit_io(struct ocf_io *io)
{
	ENV_BUG_ON(!io->obj->type->properties->ops.submit_io);

	if (!io->obj->opened)
		io->end(io, -EIO);

	io->obj->type->properties->ops.submit_io(io);
}

void ocf_dobj_submit_flush(struct ocf_io *io)
{
	ENV_BUG_ON(!io->obj->type->properties->ops.submit_flush);

	if (!io->obj->opened)
		io->end(io, -EIO);

	if (!io->obj->type->properties->ops.submit_flush) {
		ocf_io_end(io, 0); 
		return;
	}

	io->obj->type->properties->ops.submit_flush(io);
}

void ocf_dobj_submit_discard(struct ocf_io *io)
{
	if (!io->obj->opened)
		io->end(io, -EIO);

	if (!io->obj->type->properties->ops.submit_discard) {
		ocf_io_end(io, 0); 
		return;
	}

	io->obj->type->properties->ops.submit_discard(io);
}

int ocf_dobj_open(ocf_data_obj_t obj)
{
	int ret;

	ENV_BUG_ON(!obj->type->properties->ops.open);
	ENV_BUG_ON(obj->opened);

	ret = obj->type->properties->ops.open(obj);
	if (ret)
		return ret;

	obj->opened = true;

	return 0;
}

void ocf_dobj_close(ocf_data_obj_t obj)
{
	ENV_BUG_ON(!obj->type->properties->ops.close);
	ENV_BUG_ON(!obj->opened);

	obj->type->properties->ops.close(obj);
	obj->opened = false;
}

unsigned int ocf_dobj_get_max_io_size(ocf_data_obj_t obj)
{
	ENV_BUG_ON(!obj->type->properties->ops.get_max_io_size);

	if (!obj->opened)
		return 0;

	return obj->type->properties->ops.get_max_io_size(obj);
}

uint64_t ocf_dobj_get_length(ocf_data_obj_t obj)
{
	ENV_BUG_ON(!obj->type->properties->ops.get_length);

	if (!obj->opened)
		return 0;

	return obj->type->properties->ops.get_length(obj);
}
