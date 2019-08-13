/*
 * Copyright(c) 2019-2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "../ocf_cache_priv.h"

#ifndef __OCF_METADATA_CONCURRENCY_H__
#define __OCF_METADATA_CONCURRENCY_H__

#define OCF_METADATA_RD 0
#define OCF_METADATA_WR 1

void ocf_metadata_concurrency_init(struct ocf_cache *cache);

void ocf_metadata_concurrency_deinit(struct ocf_cache *cache);

int ocf_metadata_concurrency_attached_init(struct ocf_cache *cache);

static inline void ocf_metadata_eviction_lock(struct ocf_cache *cache)
{
	env_spinlock_lock(&cache->metadata.lock.eviction);
}

static inline void ocf_metadata_eviction_unlock(struct ocf_cache *cache)
{
	env_spinlock_unlock(&cache->metadata.lock.eviction);
}

#define OCF_METADATA_EVICTION_LOCK() \
		ocf_metadata_eviction_lock(cache)

#define OCF_METADATA_EVICTION_UNLOCK() \
		ocf_metadata_eviction_unlock(cache)

static inline void ocf_metadata_lock(struct ocf_cache *cache, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwsem_down_write(&cache->metadata.lock.collision);
	else if (rw == OCF_METADATA_RD)
		env_rwsem_down_read(&cache->metadata.lock.collision);
	else
		ENV_BUG();
}


static inline void ocf_metadata_unlock(struct ocf_cache *cache, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwsem_up_write(&cache->metadata.lock.collision);
	else if (rw == OCF_METADATA_RD)
		env_rwsem_up_read(&cache->metadata.lock.collision);
	else
		ENV_BUG();
}

static inline int ocf_metadata_try_lock(struct ocf_cache *cache, int rw)
{
	int result = 0;

	if (rw == OCF_METADATA_WR) {
		result = env_rwsem_down_write_trylock(
				&cache->metadata.lock.collision);
	} else if (rw == OCF_METADATA_RD) {
		result = env_rwsem_down_read_trylock(
				&cache->metadata.lock.collision);
	} else {
		ENV_BUG();
	}

	if (result)
		return -1;

	return 0;
}

static inline void ocf_metadata_status_bits_lock(
		struct ocf_cache *cache, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwlock_write_lock(&cache->metadata.lock.status);
	else if (rw == OCF_METADATA_RD)
		env_rwlock_read_lock(&cache->metadata.lock.status);
	else
		ENV_BUG();
}

static inline void ocf_metadata_status_bits_unlock(
		struct ocf_cache *cache, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwlock_write_unlock(&cache->metadata.lock.status);
	else if (rw == OCF_METADATA_RD)
		env_rwlock_read_unlock(&cache->metadata.lock.status);
	else
		ENV_BUG();
}

#define OCF_METADATA_LOCK_RD() \
		ocf_metadata_lock(cache, OCF_METADATA_RD)

#define OCF_METADATA_UNLOCK_RD() \
		ocf_metadata_unlock(cache, OCF_METADATA_RD)

#define OCF_METADATA_LOCK_RD_TRY() \
		ocf_metadata_try_lock(cache, OCF_METADATA_RD)

#define OCF_METADATA_LOCK_WR() \
		ocf_metadata_lock(cache, OCF_METADATA_WR)

#define OCF_METADATA_LOCK_WR_TRY() \
		ocf_metadata_try_lock(cache, OCF_METADATA_WR)

#define OCF_METADATA_UNLOCK_WR() \
		ocf_metadata_unlock(cache, OCF_METADATA_WR)

#define OCF_METADATA_BITS_LOCK_RD() \
		ocf_metadata_status_bits_lock(cache, OCF_METADATA_RD)

#define OCF_METADATA_BITS_UNLOCK_RD() \
		ocf_metadata_status_bits_unlock(cache, OCF_METADATA_RD)

#define OCF_METADATA_BITS_LOCK_WR() \
		ocf_metadata_status_bits_lock(cache, OCF_METADATA_WR)

#define OCF_METADATA_BITS_UNLOCK_WR() \
		ocf_metadata_status_bits_unlock(cache, OCF_METADATA_WR)

#define OCF_METADATA_FLUSH_LOCK() \
		ocf_metadata_flush_lock(cache)

#define OCF_METADATA_FLUSH_UNLOCK() \
		ocf_metadata_flush_unlock(cache)

#endif
