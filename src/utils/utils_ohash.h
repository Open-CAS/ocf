/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * ohash – hash with ordered item bucket.
 * Implementation for an ordered hash using index array, each bucket has 7 items with 64bits for each item.
 */
#ifndef __UTILS_OHASH_H__
#define __UTILS_OHASH_H__

#include "ocf/ocf_types.h"
#include "ocf_env.h"

//#define OCF_OHASH_DEBUG
#define OCF_OHASH_NAME_LEN	32
#define BUCKET_LENGTH		7

typedef struct ohash64_bucket_t {
	uint64_t items[BUCKET_LENGTH];
	uint8_t age[BUCKET_LENGTH];
	env_atomic8 lock;
} ohash64_bucket_t;

typedef struct ohash64_handle_t {
	ohash64_bucket_t *bucket;
	size_t bucket_count;
	char name[OCF_OHASH_NAME_LEN];
#ifdef OCF_OHASH_DEBUG
	env_atomic64 updated;
	env_atomic64 evicted;
	env_atomic64 called;
#endif
} ohash64_handle_t;

void ocf_ohash_create(ocf_core_t core, ohash64_handle_t *hash, size_t capacity,
		      char *name);
void ocf_ohash_destroy(ohash64_handle_t *hash);
uint64_t ocf_ohash_get_locked(ohash64_handle_t *hash, uint64_t item, uint64_t mask, bool locked);
uint64_t ocf_ohash_set_locked(ohash64_handle_t *hash, uint64_t item, uint64_t mask, bool locked);

static inline uint64_t ocf_ohash_get(ohash64_handle_t *hash, uint64_t item,
		uint64_t mask)
{
	return ocf_ohash_get_locked(hash, item, mask, false);
}

static inline uint64_t ocf_ohash_set(ohash64_handle_t *hash, uint64_t item,
		uint64_t mask)
{
	return ocf_ohash_set_locked(hash, item, mask, false);
}

static inline size_t ocf_ohash_get_capacity(ohash64_handle_t *hash)
{
	return hash->bucket_count * BUCKET_LENGTH;
}

#endif	/* __UTILS_OHASH_H__ */
