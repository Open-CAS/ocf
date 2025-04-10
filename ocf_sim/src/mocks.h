/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <ocf/ocf.h>

extern ocf_ctx_t ctx;

int open_ctrl_device();
int run_ioctl_interruptible_retry(int fd, int command, void* cmd,
		char* friendly_name, int cache_id, int core_id);
int run_ioctl(int fd, int command, void* cmd);
int run_ioctl_interruptible(int fd, int command, void* cmd,
		char* friendly_name, int cache_id, int core_id);
int create_pipe_pair(FILE** intermediate_file);


static inline void cache_name_from_id(char* name, uint16_t id)
{
	int result;

	result = snprintf(name, OCF_CACHE_NAME_SIZE, "cache%d", id);
	ENV_BUG_ON(result >= OCF_CACHE_NAME_SIZE);
}

static inline void core_name_from_id(char* name, uint16_t id)
{
	int result;

	result = snprintf(name, OCF_CORE_NAME_SIZE, "core%d", id);
	ENV_BUG_ON(result >= OCF_CORE_NAME_SIZE);
}

static inline int cache_id_from_name(uint16_t* cache_id, const char* name)
{
	const char* id_str;
	long res;

	if (strnlen(name, OCF_CACHE_NAME_SIZE) < sizeof("cache") - 1)
		return -EINVAL;

	id_str = name + sizeof("cache") - 1;

	errno = 0;
	res = strtol(id_str, NULL, 10);

	if (!errno)
		*cache_id = res;

	return errno;
}

static inline int core_id_from_name(uint16_t* core_id, const char* name)
{
	const char* id_str;
	long res;

	if (strnlen(name, OCF_CORE_NAME_SIZE) < sizeof("core") - 1)
		return -EINVAL;

	id_str = name + sizeof("core") - 1;

	errno = 0;
	res = strtol(id_str, NULL, 10);

	if (!errno)
		*core_id = res;

	return errno;
}

static inline int mngt_get_cache_by_id(ocf_ctx_t ctx, uint16_t id,
		ocf_cache_t* cache)
{
	char cache_name[OCF_CACHE_NAME_SIZE];

	cache_name_from_id(cache_name, id);

	return ocf_mngt_cache_get_by_name(ctx, cache_name,
			OCF_CACHE_NAME_SIZE, cache);
}

static inline int get_core_by_id(ocf_cache_t cache, uint16_t id,
		ocf_core_t* core)
{
	char core_name[OCF_CORE_NAME_SIZE];

	core_name_from_id(core_name, id);

	return ocf_core_get_by_name(cache, core_name, OCF_CORE_NAME_SIZE, core);
}


