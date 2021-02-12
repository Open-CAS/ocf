/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "utils_log_allocator.h"

struct ocf_log_allocator {
	uint32_t count;
	env_allocator *allocator[];
};

struct ocf_log_allocator* ocf_log_allocator_init(char* name_fmt, uint32_t count,
	size_t (*size_of)(uint32_t))
{
	uint32_t i;
	ssize_t size;
	char name[OCF_LOG_ALLOCATOR_NAME_MAX] = {0};
	struct ocf_log_allocator *alloc;

	ENV_BUG_ON(count > 32 || count < 1);

	alloc = env_zalloc(sizeof(*alloc) + (count * sizeof(env_allocator*)),
		ENV_MEM_NORMAL);
	if (!alloc)
		goto err;

	alloc->count = count;

	for (i = 0; i < count; i++) {
		size = size_of(1 << i);
		if (snprintf(name, sizeof(name), name_fmt, (1 << i)) < 0)
			goto err;

		alloc->allocator[i] = env_allocator_create(size, name);

		if (!alloc->allocator[i])
			goto err;
	}

	return alloc;

err:
	ocf_log_allocator_deinit(alloc);
	return NULL;
}

void ocf_log_allocator_deinit(struct ocf_log_allocator *allocator)
{
	uint32_t i;

	if (!allocator)
		return;

	for (i = 0; i < allocator->count; i++) {
		if (allocator->allocator[i]) {
			env_allocator_destroy(allocator->allocator[i]);
			allocator->allocator[i] = NULL;
		}
	}

	env_free(allocator);
}

env_allocator *ocf_log_allocator_get(struct ocf_log_allocator *allocator,
	uint32_t count)
{
	unsigned int idx = 31 - __builtin_clz(count);

	if (__builtin_ffs(count) <= idx)
		idx++;

	ENV_BUG_ON(count == 0);

	if (idx >= allocator->count)
		return NULL;

	return allocator->allocator[idx];
}

env_allocator *ocf_log_allocator_get_1(struct ocf_log_allocator *allocator)
{
	return allocator->allocator[0];
}

