/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "ocf/ocf.h"
#include "utils_allocator.h"
#include "../ocf_priv.h"
#include "../ocf_cache_priv.h"
#include "ocf_env.h"

#define OCF_ALLOCATOR_K_MAX	(128 * KiB)

static int _ocf_realloc_with_cp(void **mem, size_t size, size_t count,
		size_t *limit, bool cp)
{
	size_t alloc_size = size * count;

	ENV_BUG_ON(!mem);
	ENV_BUG_ON(!limit);

	if (size && count) {
		/* Memory reallocation request */

		if (alloc_size > *limit) {
			/* The space is not enough, we need allocate new one */

			void *new_mem;

			if (alloc_size > OCF_ALLOCATOR_K_MAX)
				new_mem = env_vzalloc(alloc_size);
			else
				new_mem = env_zalloc(alloc_size, ENV_MEM_NOIO);

			if (!new_mem) {
				/* Allocation error */
				return -1;
			}

			/* Free previous memory */
			if (*mem) {
				if (cp) {
					/* copy previous content into new allocated
					 * memory
					 */
					ENV_BUG_ON(env_memcpy(new_mem, alloc_size, *mem, *limit));

				}

				if (*limit > OCF_ALLOCATOR_K_MAX)
					env_vfree(*mem);
				else
					env_free(*mem);
			}

			/* Update limit */
			*limit = alloc_size;

			/* Update memory pointer */
			*mem = new_mem;

			return 0;
		}

		/*
		 * The memory space is enough, no action required.
		 * Space after allocation set to '0'
		 */
		if (cp)
			ENV_BUG_ON(env_memset(*mem + alloc_size, *limit - alloc_size, 0));

		return 0;

	}

	if ((size == 0) && (count == 0)) {

		if ((*mem) && (*limit)) {
			/* Need to free memory */
			if (*limit > OCF_ALLOCATOR_K_MAX)
				env_vfree(*mem);
			else
				env_free(*mem);

			/* Update limit */
			*((size_t *)limit) = 0;
			*mem = NULL;

			return 0;
		}

		if ((!*mem) && (*limit == 0)) {
			/* No allocation before do nothing */
			return 0;

		}
	}

	ENV_BUG();
	return -1;
}

int ocf_realloc(void **mem, size_t size, size_t count, size_t *limit)
{
	return _ocf_realloc_with_cp(mem, size, count, limit, false);
}

int ocf_realloc_cp(void **mem, size_t size, size_t count, size_t *limit)
{
	return _ocf_realloc_with_cp(mem, size, count, limit, true);
}

void ocf_realloc_init(void **mem, size_t *limit)
{
	ENV_BUG_ON(!mem);
	ENV_BUG_ON(!limit);

	*mem = NULL;
	*((size_t *)limit) = 0;
}

enum {
	ocf_mpool_1,
	ocf_mpool_2,
	ocf_mpool_4,
	ocf_mpool_8,
	ocf_mpool_16,
	ocf_mpool_32,
	ocf_mpool_64,
	ocf_mpool_128,

	ocf_mpool_max
};

struct ocf_mpool {
	struct ocf_cache *cache;
		/*!< Cache instance */

	uint32_t item_size;
		/*!< Size of specific item of memory pool */

	uint32_t hdr_size;
		/*!< Header size before items */

	env_allocator *allocator[ocf_mpool_max];
		/*!< OS handle to memory pool */

	int flags;
		/*!< Allocation flags */
};

#define ALLOCATOR_NAME_MAX 128

struct ocf_mpool *ocf_mpool_create(struct ocf_cache *cache,
		uint32_t hdr_size, uint32_t size, int flags, int mpool_max,
		const char *name_perfix)
{
	uint32_t i;
	char name[ALLOCATOR_NAME_MAX] = { '\0' };
	int result;
	struct ocf_mpool *mpool;

	OCF_CHECK_NULL(name_perfix);

	mpool = env_zalloc(sizeof(*mpool), ENV_MEM_NORMAL);
	if (!mpool)
		goto ocf_multi_allocator_create_ERROR;

	mpool->item_size = size;
	mpool->hdr_size = hdr_size;
	mpool->cache = cache;
	mpool->flags = flags;

	for (i = 0; i < min(ocf_mpool_max, mpool_max + 1); i++) {
		result = snprintf(name, sizeof(name), "%s_%u", name_perfix,
				(1 << i));
		if (result < 0 || result >= sizeof(name))
			goto ocf_multi_allocator_create_ERROR;

		mpool->allocator[i] = env_allocator_create(
				hdr_size + (size * (1 << i)), name);

		if (!mpool->allocator[i])
			goto ocf_multi_allocator_create_ERROR;
	}

	return mpool;

ocf_multi_allocator_create_ERROR:

	ocf_mpool_destroy(mpool);

	return NULL;
}

void ocf_mpool_destroy(struct ocf_mpool *mallocator)
{
	if (mallocator) {
		uint32_t i;

		for (i = 0; i < ocf_mpool_max; i++)
			if (mallocator->allocator[i])
				env_allocator_destroy(mallocator->allocator[i]);

		env_free(mallocator);
	}
}

static env_allocator *ocf_mpool_get_allocator(
	struct ocf_mpool *mallocator, uint32_t count)
{
	unsigned int idx;

	if (unlikely(count == 0))
		return ocf_mpool_1;

	idx = 31 - __builtin_clz(count);

	if (__builtin_ffs(count) <= idx)
		idx++;

	if (idx >= ocf_mpool_max)
		return NULL;

	return mallocator->allocator[idx];
}

void *ocf_mpool_new_f(struct ocf_mpool *mpool, uint32_t count, int flags)
{
	void *items = NULL;
	env_allocator *allocator;

	OCF_CHECK_NULL(mpool);

	allocator = ocf_mpool_get_allocator(mpool, count);

	if (allocator)
		items = env_allocator_new(allocator);
	else
		items = env_zalloc(mpool->hdr_size + (mpool->item_size * count), flags);

#ifdef ZERO_OR_NULL_PTR
	if (ZERO_OR_NULL_PTR(items))
		return NULL;
#endif

	return items;
}

void *ocf_mpool_new(struct ocf_mpool *mpool, uint32_t count)
{
	return ocf_mpool_new_f(mpool, count, mpool->flags);
}

void ocf_mpool_del(struct ocf_mpool *mpool,
		void *items, uint32_t count)
{
	env_allocator *allocator;

	OCF_CHECK_NULL(mpool);

	allocator = ocf_mpool_get_allocator(mpool, count);

	if (allocator)
		env_allocator_del(allocator, items);
	else
		env_free(items);
}
