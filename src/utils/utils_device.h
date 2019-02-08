/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef UTILS_DEVICE_H_
#define UTILS_DEVICE_H_

static inline int _ocf_uuid_set(const struct ocf_volume_uuid *uuid,
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

static inline int ocf_metadata_set_core_uuid(ocf_core_t core,
		const struct ocf_volume_uuid *uuid,
		struct ocf_volume_uuid *new_uuid)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	struct ocf_metadata_uuid *muuid = ocf_metadata_get_core_uuid(cache,
						ocf_core_get_id(core));

	if (_ocf_uuid_set(uuid, muuid))
		return -ENOBUFS;

	if (new_uuid) {
		new_uuid->data = muuid->data;
		new_uuid->size = muuid->size;
	}

	return 0;
}

static inline void ocf_metadata_clear_core_uuid(ocf_core_t core)
{
	struct ocf_volume_uuid uuid = { .size = 0, };

	ocf_metadata_set_core_uuid(core, &uuid, NULL);
}

#endif /* UTILS_MEM_H_ */
