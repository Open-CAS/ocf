/*
 * Copyright(c) 2019-2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_metadata_concurrency.h"

void ocf_metadata_concurrency_init(struct ocf_cache *cache)
{
	env_spinlock_init(&cache->metadata.lock.eviction);
	env_rwlock_init(&cache->metadata.lock.status);
	env_rwsem_init(&cache->metadata.lock.collision);
}

int ocf_metadata_concurrency_attached_init(struct ocf_cache *cache)
{
	return 0;
}
