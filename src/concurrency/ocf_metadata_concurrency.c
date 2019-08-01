/*
 * Copyright(c) 2019-2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_metadata_concurrency.h"
#include "../metadata/metadata_misc.h"

void ocf_metadata_concurrency_init(struct ocf_metadata_lock *metadata_lock)
{
	env_spinlock_init(&metadata_lock->eviction);
	env_rwlock_init(&metadata_lock->status);
	env_rwsem_init(&metadata_lock->global);
}

void ocf_metadata_concurrency_deinit(struct ocf_metadata_lock *metadata_lock)
{
	env_spinlock_destroy(&metadata_lock->eviction);
	env_rwlock_destroy(&metadata_lock->status);
	env_rwsem_destroy(&metadata_lock->global);
}

int ocf_metadata_concurrency_attached_init(
		struct ocf_metadata_lock *metadata_lock, ocf_cache_t cache,
		uint64_t hash_table_entries)
{
	uint64_t i;

	metadata_lock->cache = cache;
	metadata_lock->num_hash_entries = hash_table_entries;
	metadata_lock->hash = env_vzalloc(sizeof(env_rwsem) *
			hash_table_entries);
	if (!metadata_lock->hash)
		return -OCF_ERR_NO_MEM;

	for (i = 0; i < hash_table_entries; i++)
		env_rwsem_init(&metadata_lock->hash[i]);

	return 0;
}

void ocf_metadata_concurrency_attached_deinit(
		struct ocf_metadata_lock *metadata_lock)
{
	uint64_t i;

	for (i = 0; i < metadata_lock->num_hash_entries; i++)
		env_rwsem_destroy(&metadata_lock->hash[i]);

	env_vfree(metadata_lock->hash);
}

void ocf_metadata_start_exclusive_access(
		struct ocf_metadata_lock *metadata_lock)
{
        env_rwsem_down_write(&metadata_lock->global);
}

int ocf_metadata_try_start_exclusive_access(
		struct ocf_metadata_lock *metadata_lock)
{
	return env_rwsem_down_write_trylock(&metadata_lock->global);
}

void ocf_metadata_end_exclusive_access(
		struct ocf_metadata_lock *metadata_lock)
{
        env_rwsem_up_write(&metadata_lock->global);
}

void ocf_metadata_start_shared_access(
		struct ocf_metadata_lock *metadata_lock)
{
        env_rwsem_down_read(&metadata_lock->global);
}

int ocf_metadata_try_start_shared_access(
		struct ocf_metadata_lock *metadata_lock)
{
	return env_rwsem_down_read_trylock(&metadata_lock->global);
}

void ocf_metadata_end_shared_access(struct ocf_metadata_lock *metadata_lock)
{
        env_rwsem_up_read(&metadata_lock->global);
}

void ocf_metadata_hash_lock(struct ocf_metadata_lock *metadata_lock,
		ocf_cache_line_t hash, int rw)
{
	ENV_BUG_ON(hash >= metadata_lock->num_hash_entries);

	if (rw == OCF_METADATA_WR)
		env_rwsem_down_write(&metadata_lock->hash[hash]);
	else if (rw == OCF_METADATA_RD)
		env_rwsem_down_read(&metadata_lock->hash[hash]);
	else
		ENV_BUG();
}

void ocf_metadata_hash_unlock(struct ocf_metadata_lock *metadata_lock,
		ocf_cache_line_t hash, int rw)
{
	ENV_BUG_ON(hash >= metadata_lock->num_hash_entries);

	if (rw == OCF_METADATA_WR)
		env_rwsem_up_write(&metadata_lock->hash[hash]);
	else if (rw == OCF_METADATA_RD)
		env_rwsem_up_read(&metadata_lock->hash[hash]);
	else
		ENV_BUG();
}

int ocf_metadata_hash_try_lock(struct ocf_metadata_lock *metadata_lock,
		ocf_cache_line_t hash, int rw)
{
	int result = -1;

	ENV_BUG_ON(hash >= metadata_lock->num_hash_entries);

	if (rw == OCF_METADATA_WR) {
		result = env_rwsem_down_write_trylock(
				&metadata_lock->hash[hash]);
	} else if (rw == OCF_METADATA_RD) {
		result = env_rwsem_down_read_trylock(
				&metadata_lock->hash[hash]);
	} else {
		ENV_BUG();
	}

	if (!result)
		return -1;

	return 0;
}

/* NOTE: attempt to acquire hash lock for multiple core lines may end up
 * in deadlock. In order to hash lock multiple core lines safely, use
 * ocf_req_hash_lock_* functions */
void ocf_metadata_hash_lock_rd(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line)
{
	ocf_cache_line_t hash = ocf_metadata_hash_func(metadata_lock->cache,
			core_line, core_id);

	ocf_metadata_start_shared_access(metadata_lock);
	ocf_metadata_hash_lock(metadata_lock, hash, OCF_METADATA_RD);
}

void ocf_metadata_hash_unlock_rd(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line)
{
	ocf_cache_line_t hash = ocf_metadata_hash_func(metadata_lock->cache,
			core_line, core_id);

	ocf_metadata_hash_unlock(metadata_lock, hash, OCF_METADATA_RD);
	ocf_metadata_end_shared_access(metadata_lock);
}

void ocf_metadata_hash_lock_wr(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line)
{
	ocf_cache_line_t hash = ocf_metadata_hash_func(metadata_lock->cache,
			core_line, core_id);

	ocf_metadata_start_shared_access(metadata_lock);
	ocf_metadata_hash_lock(metadata_lock, hash, OCF_METADATA_WR);
}

void ocf_metadata_hash_unlock_wr(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line)
{
	ocf_cache_line_t hash = ocf_metadata_hash_func(metadata_lock->cache,
			core_line, core_id);

	ocf_metadata_hash_unlock(metadata_lock, hash, OCF_METADATA_WR);
	ocf_metadata_end_shared_access(metadata_lock);
}

#define _NUM_HASH_ENTRIES req->cache->metadata.lock.num_hash_entries

/*
 * Iterate over hash buckets for all core lines in the request in ascending hash
 * bucket value order. Each hash bucket is visited only once.
 *
 * @i is used as iteration counter, starting from 0
 * @hash stores hash values for each iteration
 * @start is internal helper variable. It set to the index of first occurence
 * of hash with minimal value within the request.
 *
 * Example hash iteration order for _NUM_HASH_ENTRIES == 5:
 *   Request hashes			Iteration order		start
 *   [2, 3, 4]				[2, 3, 4]		0
 *   [2, 3, 4, 0]		 	[0, 2, 3, 4]		3
 *   [2, 3, 4, 0, 1, 2, 3, 4, 0, 1]   	[0, 1, 2, 3, 4]		3
 *   [4, 0]				[0, 4]			1
 *   [0, 1, 2, 3, 4, 0, 1]		[0, 1, 2, 3, 4]		0
 *
 */
#define for_each_req_hash_asc(req, i, hash, start) \
	for (i = 0, start = (req->map[0].hash + req->core_line_count <= \
		_NUM_HASH_ENTRIES) ? 0 : (_NUM_HASH_ENTRIES - req->map[0].hash)\
		 % _NUM_HASH_ENTRIES, hash = req->map[start].hash; \
		i < OCF_MIN(req->core_line_count, _NUM_HASH_ENTRIES); \
		i++, hash = req->map[(start + i) % req->core_line_count].hash)

void ocf_req_hash_lock_rd(struct ocf_request *req)
{
	unsigned i, start;
	ocf_cache_line_t hash;

	ocf_metadata_start_shared_access(&req->cache->metadata.lock);
	for_each_req_hash_asc(req, i, hash, start) {
		ocf_metadata_hash_lock(&req->cache->metadata.lock, hash,
				OCF_METADATA_RD);
	}
}

void ocf_req_hash_unlock_rd(struct ocf_request *req)
{
	unsigned i, start;
	ocf_cache_line_t hash;

	for_each_req_hash_asc(req, i, hash, start) {
		ocf_metadata_hash_unlock(&req->cache->metadata.lock, hash,
				OCF_METADATA_RD);
	}
	ocf_metadata_end_shared_access(&req->cache->metadata.lock);
}

void ocf_req_hash_lock_wr(struct ocf_request *req)
{
	unsigned i, start;
	ocf_cache_line_t hash;

	ocf_metadata_start_shared_access(&req->cache->metadata.lock);
	for_each_req_hash_asc(req, i, hash, start) {
		ocf_metadata_hash_lock(&req->cache->metadata.lock, hash,
				OCF_METADATA_WR);
	}
}

void ocf_req_hash_lock_upgrade(struct ocf_request *req)
{
	unsigned i, start;
	ocf_cache_line_t hash;

	for_each_req_hash_asc(req, i, hash, start) {
		ocf_metadata_hash_unlock(&req->cache->metadata.lock, hash,
				OCF_METADATA_RD);
	}
	for_each_req_hash_asc(req, i, hash, start) {
		ocf_metadata_hash_lock(&req->cache->metadata.lock, hash,
				OCF_METADATA_WR);
	}
}

void ocf_req_hash_unlock_wr(struct ocf_request *req)
{
	unsigned i, start;
	ocf_cache_line_t hash;

	for_each_req_hash_asc(req, i, hash, start) {
		ocf_metadata_hash_unlock(&req->cache->metadata.lock, hash,
				OCF_METADATA_WR);
	}
	ocf_metadata_end_shared_access(&req->cache->metadata.lock);
}
