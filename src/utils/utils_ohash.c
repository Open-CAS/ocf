/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * ohash – hash with ordered item bucket.
 * Implementation for an ordered hash using index array,
 * each bucket has 7 items with 64bits for each item.
 */

#include "utils_ohash.h"

#include "ocf_env.h"
#include "ocf/ocf_types.h"

/* For logger */
#include "../ocf_cache_priv.h"
/* For OCF_DIV_ROUND_UP */
#include "../ocf_def_priv.h"

#ifdef OCF_OHASH_DEBUG
/* How frequently a report should be printed */
#define OCF_OHASH_REPORT_FREQ	100000

static inline void ocf_ohash_counter_update(env_atomic64 *cnt)
{
	env_atomic64_inc(cnt);
}
static inline void ocf_ohash_counter_report(ohash64_handle_t *hash)
{
	if (env_atomic64_read(&hash->called) % OCF_OHASH_REPORT_FREQ)
		return;

	printf("ohash %s called %lu evicted %lu updated %lu\n", hash->name,
		env_atomic64_read(&hash->called), env_atomic64_read(&hash->evicted), env_atomic64_read(&hash->updated));
}
#else
#define ocf_ohash_counter_update(...) { }
#define ocf_ohash_counter_report(...) { }
#endif

static inline uint64_t ocf_fast_hash_function(size_t range, uint64_t x)
{
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
        x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
        x = x ^ (x >> 31);
        return x % range;
}

/* ===========================================================================*/
/* initialize the hash function */
void ocf_ohash_create(ocf_core_t core, ohash64_handle_t *hash, size_t num_elements,
		      char *name)
{
	int i, j;
	void *p = NULL;
	size_t bucket_count = OCF_DIV_ROUND_UP(num_elements, BUCKET_LENGTH);
	/* Alloc memory and make sure bucket is processor cache line aligned */
	size_t alloc_size = bucket_count * sizeof(ohash64_bucket_t);

	if (unlikely(hash == NULL || name == NULL)) {
		ENV_WARN(true, "NULL Handle\n");
		return;
	}
	p = env_aligned_alloc(ENV_PROCESSOR_CACHE_LINE_SIZE, alloc_size);
	if (unlikely(p == NULL)) {
		ENV_WARN(true, "env_aligned_alloc(%lu) failed", alloc_size);
		return;
	}
	hash->bucket = (ohash64_bucket_t *)p;
	hash->bucket_count = bucket_count;
	env_strncpy(hash->name, sizeof(hash->name), name, env_strnlen(name, sizeof(hash->name)));

	/* Create an array of buckets */
	for (i = 0; i < bucket_count; i++) {
		env_spinlock8_init(&hash->bucket[i].lock);
		for (j = 0; j < BUCKET_LENGTH; j++) {
			hash->bucket[i].items[j] = 0;
			hash->bucket[i].age[j] = j;
		}
	}

	if (core != NULL) {
		ocf_core_log(core, log_info, "ohash %s capacity %lu\n",
			     hash->name, ocf_ohash_get_capacity(hash));
	}
}

/* ===========================================================================*/
void ocf_ohash_destroy(ohash64_handle_t *hash)
{
	if (unlikely(hash == NULL || hash->bucket == NULL)) {
		ENV_WARN(true, "NULL Handle (%p) or NULL bucket\n", hash);
	} else {
		env_aligned_free(hash->bucket);
		hash->bucket = NULL;
	}
}

/* ===========================================================================*/
/* Find an item location and return it */
uint64_t ocf_ohash_get_locked(ohash64_handle_t *hash, uint64_t item, uint64_t mask, bool locked)
{
	ohash64_bucket_t *bucket = NULL;
	uint64_t masked_item = item & mask, h;
	int i;

	if (unlikely(hash == NULL)) {
		ENV_WARN(true, "hash is NULL\n");
		return (~item & mask);
	}
	h = ocf_fast_hash_function(hash->bucket_count, masked_item);
	bucket = &hash->bucket[h];

	if (locked)
		env_spinlock8_lock(&bucket->lock);

	for (i = 0; i < BUCKET_LENGTH; i++) {
		uint64_t hash_item = *((const volatile uint64_t *)&(bucket->items[i]));
		if ((hash_item & mask) == masked_item) {
			return hash_item;
		}
	}

	return (~item & mask);
}

/* ===========================================================================*/
/* Insert an item to the hash function. */
uint64_t ocf_ohash_set_locked(ohash64_handle_t *hash, uint64_t item, uint64_t mask, bool locked)
{
	ohash64_bucket_t *bucket = NULL;
	int i;
	int item_index = -1;
	uint8_t lru_age = BUCKET_LENGTH;
	uint64_t masked_item = item & mask;
	uint64_t old_item, h;
	uint8_t item_age = 0; /* old value of the item if it already exist, otherwise stays 0 */

	h = ocf_fast_hash_function(hash->bucket_count, masked_item);
	bucket = &hash->bucket[h];

	if (unlikely(hash == NULL)) {
		ENV_WARN(true, "hash is NULL\n");
		return 0;
	}

	/* Locking the bucket */
	if (!locked)
		env_spinlock8_lock(&bucket->lock);

	for (i = 0; i < BUCKET_LENGTH; i++) {
		if (lru_age > bucket->age[i]) {
			lru_age = bucket->age[item_index = i];
		}
		/* check if the item is already in there */
		if ((bucket->items[i] & mask) == masked_item) {
			item_age = bucket->age[item_index = i];
			ocf_ohash_counter_update(&hash->updated);
			break;
		}
	}

	old_item = bucket->items[item_index];
	if (bucket->items[item_index] && ((bucket->items[item_index] & mask) != masked_item))
		ocf_ohash_counter_update(&hash->evicted);

	bucket->items[item_index] = item;
	bucket->age[item_index] = BUCKET_LENGTH;

	/* update those who were more recently used than the item to lower position. */
	for (i = 0; i < BUCKET_LENGTH; i++) {
		if (bucket->age[i] > item_age) {
			bucket->age[i]--;
		}
	}
	env_spinlock8_unlock(&bucket->lock);

	ocf_ohash_counter_update(&hash->called);
	ocf_ohash_counter_report(hash);
	return old_item;
}
