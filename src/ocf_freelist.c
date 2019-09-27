/*
 * Copyright(c) 2019-2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "metadata/metadata.h"

struct ocf_part {
        ocf_cache_line_t head;
        ocf_cache_line_t tail;
        env_atomic64 curr_size;
};

struct ocf_freelist {
	/* parent cache */
	struct ocf_cache *cache;

	/* partition list array */
	struct ocf_part *part;

	/* freelist lock array */
	env_spinlock *lock;

	/* number of free lists */
	uint32_t count;

	/* next slowpath victim idx */
	env_atomic slowpath_victim_idx;

	/* total number of free lines */
	env_atomic64 total_free;
};

static void ocf_freelist_lock(ocf_freelist_t freelist, uint32_t ctx)
{
	env_spinlock_lock(&freelist->lock[ctx]);
}

static int ocf_freelist_trylock(ocf_freelist_t freelist, uint32_t ctx)
{
	return env_spinlock_trylock(&freelist->lock[ctx]);
}

static void ocf_freelist_unlock(ocf_freelist_t freelist, uint32_t ctx)
{
	env_spinlock_unlock(&freelist->lock[ctx]);
}

/* Sets the given collision_index as the new _head_ of the Partition list. */
static void _ocf_freelist_remove_cache_line(ocf_freelist_t freelist,
		uint32_t ctx, ocf_cache_line_t cline)
{
	struct ocf_cache *cache = freelist->cache;
	struct ocf_part *freelist_part = &freelist->part[ctx];
	int is_head, is_tail;
	ocf_part_id_t invalid_part_id = PARTITION_INVALID;
	ocf_cache_line_t prev, next;
	ocf_cache_line_t line_entries = ocf_metadata_collision_table_entries(
			freelist->cache);
	uint32_t free;

	ENV_BUG_ON(cline >= line_entries);

	/* Get Partition info */
	ocf_metadata_get_partition_info(cache, cline, NULL, &next, &prev);

	/* Find out if this node is Partition _head_ */
	is_head = (prev == line_entries);
	is_tail = (next == line_entries);

	free = env_atomic64_read(&freelist_part->curr_size);

	/* Case 1: If we are head and there is only one node. So unlink node
	 * and set that there is no node left in the list.
	 */
	if (is_head && free == 1) {
		ocf_metadata_set_partition_info(cache, cline, invalid_part_id,
				line_entries, line_entries);
		freelist_part->head = line_entries;
		freelist_part->tail = line_entries;
	} else if (is_head) {
		/* Case 2: else if this collision_index is partition list head,
		 * but many nodes, update head and return
		 */
		ENV_BUG_ON(next >= line_entries);

		freelist_part->head = next;
		ocf_metadata_set_partition_prev(cache, next, line_entries);
		ocf_metadata_set_partition_next(cache, cline, line_entries);
	} else if (is_tail) {
		/* Case 3: else if this cline is partition list tail */
		ENV_BUG_ON(prev >= line_entries);

		freelist_part->tail = prev;
		ocf_metadata_set_partition_prev(cache, cline, line_entries);
		ocf_metadata_set_partition_next(cache, prev, line_entries);
	} else {
		/* Case 4: else this collision_index is a middle node.
		 * There is no change to the head and the tail pointers.
		 */

		ENV_BUG_ON(next >= line_entries || prev >= line_entries);

		/* Update prev and next nodes */
		ocf_metadata_set_partition_prev(cache, next, prev);
		ocf_metadata_set_partition_next(cache, prev, next);

		/* Update the given node */
		ocf_metadata_set_partition_info(cache, cline, invalid_part_id,
				line_entries, line_entries);
	}

	env_atomic64_dec(&freelist_part->curr_size);
	env_atomic64_dec(&freelist->total_free);
}

static ocf_cache_line_t next_phys_invalid(ocf_cache_t cache,
		ocf_cache_line_t phys)
{
	ocf_cache_line_t lg;
	ocf_cache_line_t collision_table_entries =
			ocf_metadata_collision_table_entries(cache);

	if (phys == collision_table_entries)
		return collision_table_entries;

	lg = ocf_metadata_map_phy2lg(cache, phys);
	while (metadata_test_valid_any(cache, lg)) {
		++phys;

		if (phys == collision_table_entries)
			break;

		lg = ocf_metadata_map_phy2lg(cache, phys);
	}

	return phys;
}

/* Assign unused cachelines to freelist */
void ocf_freelist_populate(ocf_freelist_t freelist,
		ocf_cache_line_t num_free_clines)
{
	unsigned step = 0;
	ocf_cache_t cache = freelist->cache;
	unsigned num_freelists = freelist->count;
	ocf_cache_line_t prev, next, idx;
	ocf_cache_line_t phys;
	ocf_cache_line_t collision_table_entries =
			ocf_metadata_collision_table_entries(cache);
	unsigned freelist_idx;
	uint64_t freelist_size;

	phys = 0;
	for (freelist_idx = 0; freelist_idx < num_freelists; freelist_idx++)
	{
		/* calculate current freelist size */
		freelist_size = num_free_clines / num_freelists;
		if (freelist_idx < (num_free_clines % num_freelists))
			++freelist_size;

		env_atomic64_set(&freelist->part[freelist_idx].curr_size,
				freelist_size);

		if (!freelist_size) {
			/* init empty freelist and move to next one */
			freelist->part[freelist_idx].head =
					collision_table_entries;
			freelist->part[freelist_idx].tail =
					collision_table_entries;
			continue;
		}

		/* find first invalid cacheline */
		phys = next_phys_invalid(cache, phys);
		ENV_BUG_ON(phys == collision_table_entries);
		idx = ocf_metadata_map_phy2lg(cache, phys);
		++phys;

		/* store freelist head */
		freelist->part[freelist_idx].head = idx;

		/* link freelist elements using partition list */
		prev = collision_table_entries;
		while (--freelist_size) {
			phys = next_phys_invalid(cache, phys);
			ENV_BUG_ON(phys == collision_table_entries);
			next = ocf_metadata_map_phy2lg(cache, phys);
			++phys;

			ocf_metadata_set_partition_info(cache, idx,
					PARTITION_INVALID, next, prev);

			prev = idx;
			idx = next;

			OCF_COND_RESCHED_DEFAULT(step);
		}

		/* terminate partition list */
		ocf_metadata_set_partition_info(cache, idx, PARTITION_INVALID,
			collision_table_entries, prev);

		/* store freelist tail */
		freelist->part[freelist_idx].tail = idx;
	}

	/* we should have reached the last invalid cache line */
	phys = next_phys_invalid(cache, phys);
	ENV_BUG_ON(phys != collision_table_entries);

	env_atomic64_set(&freelist->total_free, num_free_clines);
}

static void ocf_freelist_add_cache_line(ocf_freelist_t freelist,
		uint32_t ctx, ocf_cache_line_t line)
{
	struct ocf_cache *cache = freelist->cache;
	struct ocf_part *freelist_part = &freelist->part[ctx];
	ocf_cache_line_t tail;
	ocf_cache_line_t line_entries = ocf_metadata_collision_table_entries(
							freelist->cache);
	ocf_part_id_t invalid_part_id = PARTITION_INVALID;

	ENV_BUG_ON(line >= line_entries);

	if (env_atomic64_read(&freelist_part->curr_size) == 0) {
		freelist_part->head = line;
		freelist_part->tail = line;

		ocf_metadata_set_partition_info(cache, line, invalid_part_id,
				line_entries, line_entries);
	} else {
		tail = freelist_part->tail;

		ENV_BUG_ON(tail >= line_entries);

		ocf_metadata_set_partition_info(cache, line, invalid_part_id,
				line_entries, tail);
		ocf_metadata_set_partition_next(cache, tail, line);

		freelist_part->tail = line;
	}

	env_atomic64_inc(&freelist_part->curr_size);
	env_atomic64_inc(&freelist->total_free);
}

typedef enum {
	OCF_FREELIST_ERR_NOLOCK = 1,
	OCF_FREELIST_ERR_LIST_EMPTY,
} ocf_freelist_get_err_t;

static ocf_freelist_get_err_t ocf_freelist_get_cache_line_ctx(
		ocf_freelist_t freelist, uint32_t ctx, bool can_wait,
		ocf_cache_line_t *cline)
{
	if (env_atomic64_read(&freelist->part[ctx].curr_size) == 0)
		return -OCF_FREELIST_ERR_LIST_EMPTY;

	if (!can_wait && ocf_freelist_trylock(freelist, ctx))
		return -OCF_FREELIST_ERR_NOLOCK;

	if (can_wait)
		ocf_freelist_lock(freelist, ctx);

	if (env_atomic64_read(&freelist->part[ctx].curr_size) == 0) {
		ocf_freelist_unlock(freelist, ctx);
		return -OCF_FREELIST_ERR_LIST_EMPTY;
	}

	*cline = freelist->part[ctx].head;
	_ocf_freelist_remove_cache_line(freelist, ctx, *cline);

	ocf_freelist_unlock(freelist, ctx);

	return 0;
}

static int get_next_victim_freelist(ocf_freelist_t freelist)
{
	int ctx, next;

	do {
		ctx = env_atomic_read(&freelist->slowpath_victim_idx);
		next = (ctx + 1) % freelist->count;
	} while (ctx != env_atomic_cmpxchg(&freelist->slowpath_victim_idx, ctx,
			next));

	return ctx;
}

static bool ocf_freelist_get_cache_line_slow(ocf_freelist_t freelist,
		ocf_cache_line_t *cline)
{
	int i, ctx;
	int err;
	bool lock_err;

	/* try slowpath without waiting on lock */
	lock_err = false;
	for (i = 0; i < freelist->count; i++) {
		ctx = get_next_victim_freelist(freelist);
		err = ocf_freelist_get_cache_line_ctx(freelist, ctx, false,
				cline);
		if (!err)
			return true;
		if (err == -OCF_FREELIST_ERR_NOLOCK)
			lock_err = true;
	}

	if (!lock_err) {
		/* Slowpath failed due to empty freelists - no point in
		 * iterating through contexts to attempt slowpath with full
		 * lock */
		return false;
	}

	/* slow path with waiting on lock */
	for (i = 0; i < freelist->count; i++) {
		ctx = get_next_victim_freelist(freelist);
		if (!ocf_freelist_get_cache_line_ctx(freelist, ctx, true,
				cline)) {
			return true;
		}
	}

	return false;
}

static bool ocf_freelist_get_cache_line_fast(ocf_freelist_t freelist,
		ocf_cache_line_t *cline)
{
	bool ret;
	uint32_t ctx = env_get_execution_context();

	ret = !ocf_freelist_get_cache_line_ctx(freelist, ctx, false, cline);

	env_put_execution_context(ctx);

	return ret;
}

bool ocf_freelist_get_cache_line(ocf_freelist_t freelist,
		ocf_cache_line_t *cline)
{
	if (env_atomic64_read(&freelist->total_free) == 0)
		return false;

	if (!ocf_freelist_get_cache_line_fast(freelist, cline))
		return ocf_freelist_get_cache_line_slow(freelist, cline);

	return true;
}

void ocf_freelist_put_cache_line(ocf_freelist_t freelist,
		ocf_cache_line_t cline)
{
	uint32_t ctx = env_get_execution_context();

	ocf_freelist_lock(freelist, ctx);
	ocf_freelist_add_cache_line(freelist, ctx, cline);
	ocf_freelist_unlock(freelist, ctx);
	env_put_execution_context(ctx);
}

ocf_freelist_t ocf_freelist_init(struct ocf_cache *cache)
{
	uint32_t num;
	int i;
	ocf_freelist_t freelist;
	ocf_cache_line_t line_entries = ocf_metadata_collision_table_entries(
						cache);

	freelist = env_vzalloc(sizeof(*freelist));
	if (!freelist)
		return NULL;

	num = env_get_execution_context_count();

	freelist->cache = cache;
	freelist->count = num;
	env_atomic64_set(&freelist->total_free, 0);
	freelist->lock = env_vzalloc(sizeof(freelist->lock[0]) * num);
	freelist->part = env_vzalloc(sizeof(freelist->part[0]) * num);

	if (!freelist->lock || !freelist->part)
		goto free_allocs;

	for (i = 0; i < num; i++) {
		if (env_spinlock_init(&freelist->lock[i]))
			goto spinlock_err;

		freelist->part[i].head = line_entries;
		freelist->part[i].tail = line_entries;
		env_atomic64_set(&freelist->part[i].curr_size, 0);
	}

	return freelist;

spinlock_err:
	while (i--)
		env_spinlock_destroy(&freelist->lock[i]);
free_allocs:
	env_vfree(freelist->lock);
	env_vfree(freelist->part);
	env_vfree(freelist);
	return NULL;
}

void ocf_freelist_deinit(ocf_freelist_t freelist)
{
	int i;

	for (i = 0; i < freelist->count; i++)
		env_spinlock_destroy(&freelist->lock[i]);
	env_vfree(freelist->lock);
	env_vfree(freelist->part);
	env_vfree(freelist);
}

ocf_cache_line_t ocf_freelist_num_free(ocf_freelist_t freelist)
{
	return env_atomic64_read(&freelist->total_free);
}

