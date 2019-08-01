/*
 * Copyright(c) 2019-2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "../ocf_cache_priv.h"

#ifndef __OCF_METADATA_CONCURRENCY_H__
#define __OCF_METADATA_CONCURRENCY_H__

#define OCF_METADATA_RD 0
#define OCF_METADATA_WR 1

void ocf_metadata_concurrency_init(struct ocf_metadata_lock *metadata_lock);

void ocf_metadata_concurrency_deinit(struct ocf_metadata_lock *metadata_lock);

int ocf_metadata_concurrency_attached_init(
		struct ocf_metadata_lock *metadata_lock,
		uint64_t hash_table_entries);

void ocf_metadata_concurrency_attached_deinit(
		struct ocf_metadata_lock *metadata_lock);

static inline void ocf_metadata_eviction_lock(
		struct ocf_metadata_lock *metadata_lock)
{
	env_spinlock_lock(&metadata_lock->eviction);
}

static inline void ocf_metadata_eviction_unlock(
		struct ocf_metadata_lock *metadata_lock)
{
	env_spinlock_unlock(&metadata_lock->eviction);
}

#define OCF_METADATA_EVICTION_LOCK() \
		ocf_metadata_eviction_lock(&cache->metadata.lock)

#define OCF_METADATA_EVICTION_UNLOCK() \
		ocf_metadata_eviction_unlock(&cache->metadata.lock)

void ocf_metadata_start_exclusive_access(
		struct ocf_metadata_lock *metadata_lock);

int ocf_metadata_try_start_exclusive_access(
		struct ocf_metadata_lock *metadata_lock);

void ocf_metadata_end_exclusive_access(
		struct ocf_metadata_lock *metadata_lock);

int ocf_metadata_try_start_shared_access(
		struct ocf_metadata_lock *metadata_lock);

void ocf_metadata_start_shared_access(
		struct ocf_metadata_lock *metadata_lock);

void ocf_metadata_end_shared_access(
		struct ocf_metadata_lock *metadata_lock);

static inline void ocf_metadata_status_bits_lock(
		struct ocf_metadata_lock *metadata_lock, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwlock_write_lock(&metadata_lock->status);
	else if (rw == OCF_METADATA_RD)
		env_rwlock_read_lock(&metadata_lock->status);
	else
		ENV_BUG();
}

static inline void ocf_metadata_status_bits_unlock(
		struct ocf_metadata_lock *metadata_lock, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwlock_write_unlock(&metadata_lock->status);
	else if (rw == OCF_METADATA_RD)
		env_rwlock_read_unlock(&metadata_lock->status);
	else
		ENV_BUG();
}

#define OCF_METADATA_LOCK_RD() ocf_metadata_start_shared_access( \
		&cache->metadata.lock)

#define OCF_METADATA_UNLOCK_RD() ocf_metadata_end_shared_access( \
		&cache->metadata.lock)

#define OCF_METADATA_LOCK_RD_TRY() ocf_metadata_try_start_shared_access( \
		&cache->metadata.lock)

#define OCF_METADATA_LOCK_WR() ocf_metadata_start_exclusive_access( \
		&cache->metadata.lock)

#define OCF_METADATA_LOCK_WR_TRY() \
		ocf_metadata_try_start_exclusive_access(&cache->metadata.lock)

#define OCF_METADATA_UNLOCK_WR() ocf_metadata_end_exclusive_access( \
		&cache->metadata.lock)

#define OCF_METADATA_BITS_LOCK_RD() \
		ocf_metadata_status_bits_lock(&cache->metadata.lock, \
				OCF_METADATA_RD)

#define OCF_METADATA_BITS_UNLOCK_RD() \
		ocf_metadata_status_bits_unlock(&cache->metadata.lock, \
				OCF_METADATA_RD)

#define OCF_METADATA_BITS_LOCK_WR() \
		ocf_metadata_status_bits_lock(&cache->metadata.lock, \
				OCF_METADATA_WR)

#define OCF_METADATA_BITS_UNLOCK_WR() \
		ocf_metadata_status_bits_unlock(&cache->metadata.lock, \
				OCF_METADATA_WR)

void ocf_req_hash_lock_rd(struct ocf_request *req);
void ocf_req_hash_unlock_rd(struct ocf_request *req);
void ocf_req_hash_lock_wr(struct ocf_request *req);
void ocf_req_hash_unlock_wr(struct ocf_request *req);
void ocf_req_hash_lock_upgrade(struct ocf_request *req);

#endif
