/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef UTILS_DEVICE_H_
#define UTILS_DEVICE_H_

static inline int _ocf_uuid_set(const struct ocf_data_obj_uuid *uuid,
		struct ocf_metadata_uuid *muuid)
{
	int result;

	if (!uuid || !muuid) {
		return -EINVAL;
	}

	if (!uuid->data || !muuid->data) {
		return -EINVAL;
	}

	if (uuid->size > sizeof(muuid->data)) {
		return -ENOBUFS;
	}

	result = env_memcpy(muuid->data, sizeof(muuid->data), uuid->data, uuid->size);
	if (result)
		return result;
	result = env_memset(muuid->data + uuid->size,
			sizeof(muuid->data) - uuid->size, 0);
	if (result)
		return result;
	muuid->size = uuid->size;

	return 0;
}

static inline int ocf_uuid_cache_set(ocf_cache_t cache,
		const struct ocf_data_obj_uuid *uuid)
{
	int result;
	void *u;

	if (!uuid)
		return -EINVAL;

	u = env_vmalloc(uuid->size);
	if (!u)
		return -ENOMEM;

	cache->device->obj.uuid.size = 0;
	result = env_memcpy(u, uuid->size,
			uuid->data, uuid->size);
	if (result) {
		env_vfree(u);
		return result;
	}

	cache->device->obj.uuid.data = u;
	cache->device->obj.uuid.size = uuid->size;

	return 0;
}

static inline void ocf_uuid_cache_clear(ocf_cache_t cache)
{
	env_vfree(cache->device->obj.uuid.data);
	cache->device->obj.uuid.size = 0;
}

static inline int ocf_uuid_core_set(ocf_cache_t cache, ocf_core_t core,
		const struct ocf_data_obj_uuid *uuid)
{

	struct ocf_data_obj_uuid *cuuid = &ocf_core_get_data_object(core)->uuid;
	struct ocf_metadata_uuid *muuid = ocf_metadata_get_core_uuid(cache,
						ocf_core_get_id(core));
	if (_ocf_uuid_set(uuid, muuid)) {
		return -ENOBUFS;
	}

	cuuid->data = muuid->data;
	cuuid->size = muuid->size;

	return 0;
}

static inline void ocf_uuid_core_clear(ocf_cache_t cache, ocf_core_t core)
{
	struct ocf_data_obj_uuid uuid = { .size = 0, };
	ocf_uuid_core_set(cache, core, &uuid);
}

#endif /* UTILS_MEM_H_ */
