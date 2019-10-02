/*
 * Copyright(c) 2019-2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_metadata_concurrency.h"
#include "../metadata/metadata_misc.h"

int ocf_metadata_concurrency_init(struct ocf_metadata_lock *metadata_lock)
{
	int err = 0;
	unsigned i;

	err = env_spinlock_init(&metadata_lock->eviction);
	if (err)
		return err;

	env_rwlock_init(&metadata_lock->status);
	err = env_rwsem_init(&metadata_lock->global);
	if (err)
		goto rwsem_err;

	for (i = 0; i < OCF_IO_CLASS_MAX; i++) {
		err = env_spinlock_init(&metadata_lock->partition[i]);
		if (err)
			goto spinlocks_err;
	}

	return err;

spinlocks_err:
	while (i--)
		env_spinlock_destroy(&metadata_lock->partition[i]);
rwsem_err:
	env_rwlock_destroy(&metadata_lock->status);
	env_spinlock_destroy(&metadata_lock->eviction);
	return err;
}

void ocf_metadata_concurrency_deinit(struct ocf_metadata_lock *metadata_lock)
{
	unsigned i;

	for (i = 0; i < OCF_IO_CLASS_MAX; i++) {
		env_spinlock_destroy(&metadata_lock->partition[i]);
	}

	env_spinlock_destroy(&metadata_lock->eviction);
	env_rwlock_destroy(&metadata_lock->status);
	env_rwsem_destroy(&metadata_lock->global);
}

int ocf_metadata_concurrency_attached_init(
		struct ocf_metadata_lock *metadata_lock, ocf_cache_t cache,
		uint32_t hash_table_entries, uint32_t colision_table_pages)
{
	uint32_t i;
	int err = 0;

	metadata_lock->hash = env_vzalloc(sizeof(env_rwsem) *
			hash_table_entries);
	metadata_lock->collision_pages = env_vzalloc(sizeof(env_rwsem) *
			colision_table_pages);
	if (!metadata_lock->hash ||
			!metadata_lock->collision_pages) {
		env_vfree(metadata_lock->hash);
		env_vfree(metadata_lock->collision_pages);
		metadata_lock->hash = NULL;
		metadata_lock->collision_pages = NULL;
		return -OCF_ERR_NO_MEM;
	}

	for (i = 0; i < hash_table_entries; i++) {
		err = env_rwsem_init(&metadata_lock->hash[i]);
		if (err)
			 break;
	}
	if (err) {
		while (i--)
			env_rwsem_destroy(&metadata_lock->hash[i]);
		env_vfree(metadata_lock->hash);
		metadata_lock->hash = NULL;
		ocf_metadata_concurrency_attached_deinit(metadata_lock);
		return err;
	}


	for (i = 0; i < colision_table_pages; i++) {
		err = env_rwsem_init(&metadata_lock->collision_pages[i]);
		if (err)
			break;
	}
	if (err) {
		while (i--)
			env_rwsem_destroy(&metadata_lock->collision_pages[i]);
		env_vfree(metadata_lock->collision_pages);
		metadata_lock->collision_pages = NULL;
		ocf_metadata_concurrency_attached_deinit(metadata_lock);
		return err;
	}

	metadata_lock->cache = cache;
	metadata_lock->num_hash_entries = hash_table_entries;
	metadata_lock->num_collision_pages = colision_table_pages;

	return 0;
}

void ocf_metadata_concurrency_attached_deinit(
		struct ocf_metadata_lock *metadata_lock)
{
	uint32_t i;

	if (metadata_lock->hash) {
		for (i = 0; i < metadata_lock->num_hash_entries; i++)
			env_rwsem_destroy(&metadata_lock->hash[i]);
		env_vfree(metadata_lock->hash);
		metadata_lock->hash = NULL;
		metadata_lock->num_hash_entries = 0;
	}

	if (metadata_lock->collision_pages) {
		for (i = 0; i < metadata_lock->num_collision_pages; i++)
			env_rwsem_destroy(&metadata_lock->collision_pages[i]);
		env_vfree(metadata_lock->collision_pages);
		metadata_lock->collision_pages = NULL;
		metadata_lock->num_collision_pages = 0;
	}
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

/* number of hash entries */
#define _NUM_HASH_ENTRIES req->cache->metadata.lock.num_hash_entries

/* true if hashes are monotonic */
#define _IS_MONOTONIC(req) (req->map[0].hash + req->core_line_count <= \
		_NUM_HASH_ENTRIES)

/* minimal hash value */
#define _MIN_HASH(req) (_IS_MONOTONIC(req) ? req->map[0].hash : 0)

/* maximal hash value */
#define _MAX_HASH(req) (_IS_MONOTONIC(req) ? \
		req->map[req->core_line_count - 1].hash : \
		_NUM_HASH_ENTRIES - 1)

/* number of unique hash values in request */
#define _HASH_COUNT(req) OCF_MIN(req->core_line_count, _NUM_HASH_ENTRIES)

/* true if there is a gap in hash values */
#define _HAS_GAP(req) (_MAX_HASH(req) - _MIN_HASH(req) + 1 > _HASH_COUNT(req))

/* gap size */
#define _GAP_VAL(req) ((_MAX_HASH(req) - _MIN_HASH(req) + 1) - _HASH_COUNT(req))

/* hash value after which there is a gap */
#define _GAP_START(req) req->map[req->core_line_count - 1].hash

/* get next hash value */
#define _HASH_NEXT(req, hash) (hash + 1 + \
		((_HAS_GAP(req) && hash == _GAP_START(req)) ? _GAP_VAL(req) : 0))

/*
 * Iterate over hash buckets for all core lines in the request in ascending hash
 * bucket value order. Each hash bucket is visited only once.
 *
 * @hash stores hash values for each iteration
 *
 * Example hash iteration order for _NUM_HASH_ENTRIES == 5:
 *   Request hashes			Iteration order
 *   [2, 3, 4]				[2, 3, 4]
 *   [2, 3, 4, 0]		 	[0, 2, 3, 4]
 *   [2, 3, 4, 0, 1, 2, 3, 4, 0, 1]   	[0, 1, 2, 3, 4]
 *   [4, 0]				[0, 4]
 *   [0, 1, 2, 3, 4, 0, 1]		[0, 1, 2, 3, 4]
 *
 */
#define for_each_req_hash_asc(req, hash) \
	for (hash = _MIN_HASH(req); hash <= _MAX_HASH(req); \
			hash = _HASH_NEXT(req, hash))

void ocf_req_hash_lock_rd(struct ocf_request *req)
{
	ocf_cache_line_t hash;

	ocf_metadata_start_shared_access(&req->cache->metadata.lock);
	for_each_req_hash_asc(req, hash) {
		ocf_metadata_hash_lock(&req->cache->metadata.lock, hash,
				OCF_METADATA_RD);
	}
}

void ocf_req_hash_unlock_rd(struct ocf_request *req)
{
	ocf_cache_line_t hash;

	for_each_req_hash_asc(req, hash) {
		ocf_metadata_hash_unlock(&req->cache->metadata.lock, hash,
				OCF_METADATA_RD);
	}
	ocf_metadata_end_shared_access(&req->cache->metadata.lock);
}

void ocf_req_hash_lock_wr(struct ocf_request *req)
{
	ocf_cache_line_t hash;

	ocf_metadata_start_shared_access(&req->cache->metadata.lock);
	for_each_req_hash_asc(req, hash) {
		ocf_metadata_hash_lock(&req->cache->metadata.lock, hash,
				OCF_METADATA_WR);
	}
}

void ocf_req_hash_lock_upgrade(struct ocf_request *req)
{
	ocf_cache_line_t hash;

	for_each_req_hash_asc(req, hash) {
		ocf_metadata_hash_unlock(&req->cache->metadata.lock, hash,
				OCF_METADATA_RD);
	}
	for_each_req_hash_asc(req, hash) {
		ocf_metadata_hash_lock(&req->cache->metadata.lock, hash,
				OCF_METADATA_WR);
	}
}

void ocf_req_hash_unlock_wr(struct ocf_request *req)
{
	ocf_cache_line_t hash;

	for_each_req_hash_asc(req, hash) {
		ocf_metadata_hash_unlock(&req->cache->metadata.lock, hash,
				OCF_METADATA_WR);
	}
	ocf_metadata_end_shared_access(&req->cache->metadata.lock);
}

void ocf_collision_start_shared_access(struct ocf_metadata_lock *metadata_lock,
		uint32_t page)
{
	env_rwsem_down_read(&metadata_lock->collision_pages[page]);
}

void ocf_collision_end_shared_access(struct ocf_metadata_lock *metadata_lock,
		uint32_t page)
{
	env_rwsem_up_read(&metadata_lock->collision_pages[page]);
}

void ocf_collision_start_exclusive_access(struct ocf_metadata_lock *metadata_lock,
		uint32_t page)
{
	env_rwsem_down_write(&metadata_lock->collision_pages[page]);
}

void ocf_collision_end_exclusive_access(struct ocf_metadata_lock *metadata_lock,
		uint32_t page)
{
	env_rwsem_up_write(&metadata_lock->collision_pages[page]);
}
