/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "eviction.h"
#include "lru.h"
#include "ops.h"
#include "../utils/utils_cleaner.h"
#include "../utils/utils_cache_line.h"
#include "../concurrency/ocf_concurrency.h"
#include "../mngt/ocf_mngt_common.h"
#include "../engine/engine_zero.h"
#include "../ocf_cache_priv.h"
#include "../ocf_request.h"
#include "../engine/engine_common.h"


#define OCF_EVICTION_MAX_SCAN 1024

static inline struct ocf_lru_list *evp_get_cline_list(ocf_cache_t cache,
		ocf_cache_line_t cline);
static struct ocf_lru_list *evp_lru_get_list(struct ocf_part_runtime *part,
		uint32_t evp, bool clean);

static const ocf_cache_line_t end_marker = (ocf_cache_line_t)-1;


static inline struct lru_eviction_policy_meta* ocf_get_lru(ocf_cache_t cache,
		ocf_cache_line_t cline)
{
	return &ocf_metadata_get_eviction_policy(cache, cline)->lru;
}

/* update list last_hot index. returns pivot element (the one for which hot
 * status effectively changes during balancing). */
static inline ocf_cache_line_t balance_update_last_hot(ocf_cache_t cache,
		struct ocf_lru_list *list, int change)
{
	ocf_cache_line_t last_hot_new, last_hot_old;

	last_hot_old = list->last_hot;

	if (change > 0) {
		ENV_BUG_ON(change != 1);

		if (list->last_hot == end_marker) {
			last_hot_new = list->head;
		} else {
			last_hot_new = ocf_get_lru(cache, list->last_hot)->next;
			ENV_BUG_ON(last_hot_new == end_marker);
		}
	} else if (change < 0) {
		ENV_BUG_ON(change != -1);
		ENV_BUG_ON(list->last_hot == end_marker);

		last_hot_new = ocf_get_lru(cache, list->last_hot)->prev;
	} else {
		last_hot_new = list->last_hot;
	}

	list->last_hot = last_hot_new;

	if (change == 0)
		return end_marker;

	return (change > 0) ? list->last_hot : last_hot_old;
}

/* Increase / decrease number of hot elements to achieve target count.
 * Asssumes that the list has hot element clustered together at the
 * head of the list.
 */
static void balance_lru_list(ocf_cache_t cache, struct ocf_lru_list *list)
{
	unsigned target_hot_count = list->num_nodes / OCF_LRU_HOT_RATIO;
	int change = target_hot_count - list->num_hot;
	ocf_cache_line_t pivot;

	/* 1 - update hot counter */
	list->num_hot = target_hot_count;

	/* 2 - update last hot */
	pivot = balance_update_last_hot(cache, list, change);

	/* 3 - change hot bit for cacheline at the end of hot list */
	if (pivot != end_marker)
		ocf_get_lru(cache, pivot)->hot = (change >= 0);
}

/* Adds the given collision_index to the _head_ of the LRU list */
static void add_lru_head_nobalance(ocf_cache_t cache,
		struct ocf_lru_list *list,
		unsigned int collision_index)
{
	struct lru_eviction_policy_meta *node;
	unsigned int curr_head_index;

	ENV_BUG_ON(collision_index == end_marker);

	node = ocf_get_lru(cache, collision_index);
	node->hot = false;

	/* First node to be added/ */
	if (!list->num_nodes)  {
		list->head = collision_index;
		list->tail = collision_index;

		node->next = end_marker;
		node->prev = end_marker;

		list->num_nodes = 1;
	} else {
		struct lru_eviction_policy_meta *curr_head;

		/* Not the first node to be added. */
		curr_head_index = list->head;

		ENV_BUG_ON(curr_head_index == end_marker);

		curr_head = ocf_get_lru(cache, curr_head_index);

		node->next = curr_head_index;
		node->prev = end_marker;
		curr_head->prev = collision_index;
		node->hot = true;
		if (!curr_head->hot)
			list->last_hot = collision_index;
		++list->num_hot;

		list->head = collision_index;

		++list->num_nodes;
	}
}

static void add_lru_head(ocf_cache_t cache, struct ocf_lru_list *list,
		ocf_part_id_t part_id, bool clean,
		ocf_cache_line_t collision_index)
{
	add_lru_head_nobalance(cache, list, collision_index);
	balance_lru_list(cache, list);
}

/* update list global pointers and node neghbours to reflect removal */
static inline void remove_update_ptrs(ocf_cache_t cache,
		struct ocf_lru_list *list,
		unsigned int collision_index,
		struct lru_eviction_policy_meta *node)
{
	uint32_t next_lru_node = node->next;
	uint32_t prev_lru_node = node->prev;

	bool is_head = (node->prev == end_marker);
	bool is_tail = (node->next == end_marker);

	if (is_head && is_tail) {
		list->head = end_marker;
		list->tail = end_marker;
	} else if (is_head) {
		struct lru_eviction_policy_meta *next_node;

		next_node = ocf_get_lru(cache, next_lru_node);
		list->head = next_lru_node;
		next_node->prev = end_marker;
	} else if (is_tail) {
		struct lru_eviction_policy_meta *prev_node;

		list->tail = prev_lru_node;
		prev_node = ocf_get_lru(cache, prev_lru_node);
		prev_node->next = end_marker;
	} else {
		struct lru_eviction_policy_meta *prev_node;
		struct lru_eviction_policy_meta *next_node;

		next_node = ocf_get_lru(cache, next_lru_node);
		prev_node = ocf_get_lru(cache, prev_lru_node);

		/* Update prev and next nodes */
		prev_node->next = node->next;
		next_node->prev = node->prev;
	}

	if (list->last_hot == collision_index)
		list->last_hot = prev_lru_node;
}

/* Deletes the node with the given collision_index from the lru list */
static void remove_lru_list_nobalance(ocf_cache_t cache, struct ocf_lru_list *list,
		ocf_cache_line_t collision_index)
{
	int is_head = 0, is_tail = 0;
	struct lru_eviction_policy_meta *node;

	ENV_BUG_ON(collision_index == end_marker);

	node = ocf_get_lru(cache, collision_index);

	is_head = (list->head == collision_index);
	is_tail = (list->tail == collision_index);

	ENV_BUG_ON(is_head == (node->prev != end_marker));
	ENV_BUG_ON(is_tail == (node->next != end_marker));

	remove_update_ptrs(cache, list, collision_index, node);

	--list->num_nodes;
	if (node->hot)
		--list->num_hot;

	node->next = end_marker;
	node->prev = end_marker;
	node->hot = false;
}

static void remove_lru_list(ocf_cache_t cache, struct ocf_lru_list *list,
		ocf_part_id_t part_id, bool clean, ocf_cache_line_t cline)
{
	remove_lru_list_nobalance(cache, list, cline);
	balance_lru_list(cache, list);
}

static void evp_lru_set_hot(ocf_cache_t cache, struct ocf_lru_list *list,
		ocf_part_id_t part_id, bool clean, ocf_cache_line_t cline)

{
	remove_lru_list_nobalance(cache, list, cline);
	add_lru_head_nobalance(cache, list, cline);
	balance_lru_list(cache, list);
}

static struct ocf_lru_list *evp_lru_get_list(struct ocf_part_runtime *part,
		uint32_t evp, bool clean)
{
	return clean ? &part->eviction[evp].policy.lru.clean :
			&part->eviction[evp].policy.lru.dirty;
}

static inline struct ocf_lru_list *evp_get_cline_list(ocf_cache_t cache,
		ocf_cache_line_t cline)
{
	uint32_t ev_list = (cline % OCF_NUM_EVICTION_LISTS);
	ocf_part_id_t part_id;
	struct ocf_part_runtime *part;

	part_id = ocf_metadata_get_partition_id(cache, cline);

	if (part_id == PARTITION_INVALID)
		return evp_lru_get_list(cache->free, ev_list, true);

	part = cache->user_parts[part_id].runtime;

	return evp_lru_get_list(part, ev_list,
			!metadata_test_dirty(cache, cline));
}

static void evp_lru_move(ocf_cache_t cache, ocf_cache_line_t cline, bool clean,
		struct ocf_part_runtime *src_part, struct ocf_lru_list *src_list,
		struct ocf_part_runtime *dst_part, struct ocf_lru_list *dst_list,
		ocf_part_id_t src_part_id, ocf_part_id_t dst_part_id)
{
	remove_lru_list(cache, src_list, src_part_id, clean, cline);
	add_lru_head(cache, dst_list, dst_part_id, clean, cline);
}

static void evp_lru_repart_locked(ocf_cache_t cache, ocf_cache_line_t cline,
		struct ocf_part_runtime *src_part, ocf_part_id_t src_part_id,
		struct ocf_part_runtime *dst_part, ocf_part_id_t dst_part_id)
{
	uint32_t ev_list = (cline % OCF_NUM_EVICTION_LISTS);
	bool clean;
	struct ocf_lru_list *src_list, *dst_list;

	clean = !metadata_test_dirty(cache, cline);

	ENV_BUG_ON(!clean && (dst_part_id == PARTITION_INVALID ||
				src_part_id == PARTITION_INVALID));

	src_list = evp_lru_get_list(src_part, ev_list, clean);
	dst_list = evp_lru_get_list(dst_part, ev_list, clean);

	evp_lru_move(cache, cline, clean, src_part, src_list,
			dst_part, dst_list, src_part_id, dst_part_id);

	ocf_metadata_set_partition_id(cache, cline, dst_part_id);

	/* curr_size update is not journaled as it is not needed (value can
	 * be derived from the size of corresponding LRU lists)
	 */
	env_atomic_dec(&src_part->curr_size);
	env_atomic_inc(&dst_part->curr_size);
}

void ocf_lru_repart(ocf_cache_t cache, ocf_cache_line_t cline,
		struct ocf_user_part *src_part,
		struct ocf_user_part *dst_part)
{
	OCF_METADATA_EVICTION_WR_LOCK(cline);
	evp_lru_repart_locked(cache, cline, src_part->runtime, src_part->id,
			dst_part->runtime, dst_part->id);
	OCF_METADATA_EVICTION_WR_UNLOCK(cline);
}

/* the caller must hold the metadata lock */
void evp_lru_rm_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache, cline);
	struct ocf_part_runtime *part = cache->user_parts[part_id].runtime;

	evp_lru_repart_locked(cache, cline, part, part_id,
			cache->free, PARTITION_INVALID);

}


static inline void lru_iter_init(struct ocf_lru_iter *iter, ocf_cache_t cache,
		struct ocf_part_runtime *part, ocf_part_id_t part_id,
		uint32_t start_evp, bool clean,
		_lru_hash_locked_pfn hash_locked, struct ocf_request *req)
{
	uint32_t i;

	/* entire iterator implementation depends on gcc builtins for
	   bit operations which works on 64 bit integers at most */
	ENV_BUILD_BUG_ON(OCF_NUM_EVICTION_LISTS > sizeof(iter->evp) * 8);

	iter->cache = cache;
	iter->c = ocf_cache_line_concurrency(cache);
	iter->part = part;
	/* set iterator value to start_evp - 1 modulo OCF_NUM_EVICTION_LISTS */
	iter->evp = (start_evp + OCF_NUM_EVICTION_LISTS - 1) %
			OCF_NUM_EVICTION_LISTS;
	iter->num_avail_evps = OCF_NUM_EVICTION_LISTS;
	iter->next_avail_evp = ((1ULL << OCF_NUM_EVICTION_LISTS) - 1);
	iter->clean = clean;
	iter->hash_locked = hash_locked;
	iter->req = req;

	for (i = 0; i < OCF_NUM_EVICTION_LISTS; i++)
		iter->curr_cline[i] = evp_lru_get_list(part, i, clean)->tail;
}

static inline void lru_iter_cleaning_init(struct ocf_lru_iter *iter,
		ocf_cache_t cache, struct ocf_part_runtime *part,
		ocf_part_id_t part_id, uint32_t start_evp)
{
	/* Lock cachelines for read, non-exclusive access */
	lru_iter_init(iter, cache, part, part_id, start_evp, false, NULL, NULL);
}

static inline void lru_iter_eviction_init(struct ocf_lru_iter *iter,
		ocf_cache_t cache, struct ocf_part_runtime *part,
		ocf_part_id_t part_id, uint32_t start_evp,
		struct ocf_request *req)
{
	/* Lock hash buckets for write, cachelines according to user request,
	 * however exclusive cacheline access is needed even in case of read
	 * access. _evp_lru_evict_hash_locked tells whether given hash bucket
	 * is already locked as part of request hash locking (to avoid attempt
	 * to acquire the same hash bucket lock twice) */
	lru_iter_init(iter, cache, part, part_id, start_evp, true,
			ocf_req_hash_in_range, req);
}


static inline uint32_t _lru_next_evp(struct ocf_lru_iter *iter)
{
	unsigned increment;

	increment = __builtin_ffsll(iter->next_avail_evp);
	iter->next_avail_evp = ocf_rotate_right(iter->next_avail_evp,
			increment, OCF_NUM_EVICTION_LISTS);
	iter->evp = (iter->evp + increment) % OCF_NUM_EVICTION_LISTS;

	return iter->evp;
}



static inline bool _lru_evp_is_empty(struct ocf_lru_iter *iter)
{
	return !(iter->next_avail_evp & (1ULL << (OCF_NUM_EVICTION_LISTS - 1)));
}

static inline void _lru_evp_set_empty(struct ocf_lru_iter *iter)
{
	iter->next_avail_evp &= ~(1ULL << (OCF_NUM_EVICTION_LISTS - 1));
	iter->num_avail_evps--;
}

static inline bool _lru_evp_all_empty(struct ocf_lru_iter *iter)
{
	return iter->num_avail_evps == 0;
}

static bool inline _lru_trylock_hash(struct ocf_lru_iter *iter,
		ocf_core_id_t core_id, uint64_t core_line)
{
	if (iter->hash_locked != NULL && iter->hash_locked(
				iter->req, core_id, core_line)) {
		return true;
	}

	return ocf_hb_cline_naked_trylock_wr(
			&iter->cache->metadata.lock,
			core_id, core_line);
}

static void inline _lru_unlock_hash(struct ocf_lru_iter *iter,
		ocf_core_id_t core_id, uint64_t core_line)
{
	if (iter->hash_locked != NULL && iter->hash_locked(
				iter->req, core_id, core_line)) {
		return;
	}

	ocf_hb_cline_naked_unlock_wr(
			&iter->cache->metadata.lock,
			core_id, core_line);
}

static bool inline _lru_iter_evition_lock(struct ocf_lru_iter *iter,
		ocf_cache_line_t cache_line,
		ocf_core_id_t *core_id, uint64_t *core_line)

{
	struct ocf_request *req = iter->req;

	if (!ocf_cache_line_try_lock_wr(iter->c, cache_line))
		return false;

	ocf_metadata_get_core_info(iter->cache, cache_line,
		core_id, core_line);

	/* avoid evicting current request target cachelines */
	if (*core_id == ocf_core_get_id(req->core) &&
			*core_line >= req->core_line_first &&
			*core_line <= req->core_line_last) {
		ocf_cache_line_unlock_wr(iter->c, cache_line);
		return false;
	}

	if (!_lru_trylock_hash(iter, *core_id, *core_line)) {
		ocf_cache_line_unlock_wr(iter->c, cache_line);
		return false;
	}

	if (ocf_cache_line_are_waiters(iter->c, cache_line)) {
		_lru_unlock_hash(iter, *core_id, *core_line);
		ocf_cache_line_unlock_wr(iter->c, cache_line);
		return false;
	}

	return true;
}

/* Get next clean cacheline from tail of lru lists. Caller must not hold any
 * eviction list lock.
 * - returned cacheline is write locked
 * - returned cacheline has the corresponding metadata hash bucket write locked
 * - cacheline is moved to the head of destination partition lru list before
 *   being returned.
 * All this is packed into a single function to lock LRU list once per each
 * replaced cacheline.
 **/
static inline ocf_cache_line_t lru_iter_eviction_next(struct ocf_lru_iter *iter,
		struct ocf_part_runtime *dst_part, ocf_part_id_t dst_part_id,
		ocf_core_id_t *core_id, uint64_t *core_line)
{
	uint32_t curr_evp;
	ocf_cache_line_t  cline;
	ocf_cache_t cache = iter->cache;
	struct ocf_part_runtime *part = iter->part;
	struct ocf_lru_list *list;

	do {
		curr_evp = _lru_next_evp(iter);

		ocf_metadata_eviction_wr_lock(&cache->metadata.lock, curr_evp);

		list = evp_lru_get_list(part, curr_evp, iter->clean);

		cline = list->tail;
		while (cline != end_marker && !_lru_iter_evition_lock(iter,
				cline, core_id, core_line)) {
			cline = ocf_get_lru(iter->cache, cline)->prev;
		}

		if (cline != end_marker) {
			if (dst_part != part) {
				evp_lru_repart_locked(cache, cline,
						part, iter->part_id,
						dst_part, dst_part_id);
			} else {
				evp_lru_set_hot(cache, list, dst_part_id, true,
						cline);
			}
		}

		ocf_metadata_eviction_wr_unlock(&cache->metadata.lock,
				curr_evp);

		if (cline == end_marker && !_lru_evp_is_empty(iter)) {
			/* mark list as empty */
			_lru_evp_set_empty(iter);
		}
	} while (cline == end_marker && !_lru_evp_all_empty(iter));

	return cline;
}

/* Get next clean cacheline from tail of free lru lists. Caller must not hold any
 * eviction list lock.
 * - returned cacheline is write locked
 * - cacheline is moved to the head of destination partition lru list before
 *   being returned.
 * All this is packed into a single function to lock LRU list once per each
 * replaced cacheline.
 **/
static inline ocf_cache_line_t lru_iter_free_next(struct ocf_lru_iter *iter,
		struct ocf_part_runtime *dst_part, ocf_part_id_t dst_part_id)
{
	uint32_t curr_evp;
	ocf_cache_line_t cline;
	ocf_cache_t cache = iter->cache;
	struct ocf_part_runtime *free = iter->part;
	struct ocf_lru_list *list;

	do {
		curr_evp = _lru_next_evp(iter);

		ocf_metadata_eviction_wr_lock(&cache->metadata.lock, curr_evp);

		list = evp_lru_get_list(free, curr_evp, iter->clean);

		cline = list->tail;
		while (cline != end_marker && !ocf_cache_line_try_lock_wr(
				iter->c, cline)) {
			cline = ocf_get_lru(iter->cache, cline)->prev;
		}

		if (cline != end_marker) {
			ENV_BUG_ON(dst_part == free);
			evp_lru_repart_locked(cache, cline, free,
					PARTITION_INVALID, dst_part, dst_part_id);
		}

		ocf_metadata_eviction_wr_unlock(&cache->metadata.lock,
				curr_evp);

		if (cline == end_marker && !_lru_evp_is_empty(iter)) {
			/* mark list as empty */
			_lru_evp_set_empty(iter);
		}
	} while (cline == end_marker && !_lru_evp_all_empty(iter));

	return cline;
}

/* Get next dirty cacheline from tail of lru lists. Caller must hold all
 * eviction list locks during entire iteration proces. Returned cacheline
 * is read or write locked, depending on iter->write_lock */
static inline ocf_cache_line_t lru_iter_cleaning_next(struct ocf_lru_iter *iter)
{
	uint32_t curr_evp;
	ocf_cache_line_t  cline;

	do {
		curr_evp = _lru_next_evp(iter);
		cline = iter->curr_cline[curr_evp];

		while (cline != end_marker && ! ocf_cache_line_try_lock_rd(
				iter->c, cline)) {
			cline = ocf_get_lru(iter->cache, cline)->prev;
		}
		if (cline != end_marker) {
			iter->curr_cline[curr_evp] =
				ocf_get_lru(iter->cache , cline)->prev;
		}

		if (cline == end_marker && !_lru_evp_is_empty(iter)) {
			/* mark list as empty */
			_lru_evp_set_empty(iter);
		}
	} while (cline == end_marker && !_lru_evp_all_empty(iter));

	return cline;
}

static void evp_lru_clean_end(void *private_data, int error)
{
	struct ocf_part_cleaning_ctx *ctx = private_data;
	unsigned i;

	for (i = 0; i < OCF_EVICTION_CLEAN_SIZE; i++) {
		if (ctx->cline[i] != end_marker)
			ocf_cache_line_unlock_rd(ctx->cache->device->concurrency
					.cache_line, ctx->cline[i]);
	}

	ocf_refcnt_dec(&ctx->counter);
}

static int evp_lru_clean_get(ocf_cache_t cache, void *getter_context,
		uint32_t idx, ocf_cache_line_t *line)
{
	struct ocf_part_cleaning_ctx *ctx = getter_context;

	if (ctx->cline[idx] == end_marker)
		return -1;

	*line = ctx->cline[idx];

	return 0;
}

void evp_lru_clean(ocf_cache_t cache, struct ocf_user_part *part,
		struct ocf_part_cleaning_ctx *ctx,
		ocf_queue_t io_queue, uint32_t count)
{
	struct ocf_cleaner_attribs attribs = {
		.lock_cacheline = false,
		.lock_metadata = true,
		.do_sort = true,

		.cmpl_context = ctx,
		.cmpl_fn = evp_lru_clean_end,

		.getter = evp_lru_clean_get,
		.getter_context = &part->runtime->cleaning,

		.count = min(count, OCF_EVICTION_CLEAN_SIZE),

		.io_queue = io_queue
	};
	ocf_cache_line_t *cline = ctx->cline;
	struct ocf_lru_iter iter;
	unsigned evp;
	int cnt;
	unsigned i;
	unsigned lock_idx;

	if (ocf_mngt_cache_is_locked(cache))
		return;
	cnt = ocf_refcnt_inc(&ctx->counter);
	if (!cnt) {
		/* cleaner disabled by management operation */
		return;
	}

	if (cnt > 1) {
		/* cleaning already running for this partition */
		ocf_refcnt_dec(&ctx->counter);
		return;
	}

	ctx->cache = cache;
	evp = io_queue->eviction_idx++ % OCF_NUM_EVICTION_LISTS;

	lock_idx = ocf_metadata_concurrency_next_idx(io_queue);
	ocf_metadata_start_shared_access(&cache->metadata.lock, lock_idx);

	OCF_METADATA_EVICTION_WR_LOCK_ALL();

	lru_iter_cleaning_init(&iter, cache, part->runtime, part->id, evp);
	i = 0;
	while (i < OCF_EVICTION_CLEAN_SIZE) {
		cline[i] = lru_iter_cleaning_next(&iter);
		if (cline[i] == end_marker)
			break;
		i++;
	}
	while (i < OCF_EVICTION_CLEAN_SIZE)
		cline[i++] = end_marker;

	OCF_METADATA_EVICTION_WR_UNLOCK_ALL();

	ocf_metadata_end_shared_access(&cache->metadata.lock, lock_idx);

	ocf_cleaner_fire(cache, &attribs);
}

bool evp_lru_can_evict(ocf_cache_t cache)
{
	if (env_atomic_read(&cache->pending_eviction_clines) >=
			OCF_PENDING_EVICTION_LIMIT) {
		return false;
	}

	return true;
}

static void evp_lru_invalidate(ocf_cache_t cache, ocf_cache_line_t cline,
	ocf_core_id_t core_id, ocf_part_id_t part_id)
{
	ocf_core_t core;

	ocf_metadata_start_collision_shared_access(
			cache, cline);
	metadata_clear_valid_sec(cache, cline, 0,
			ocf_line_end_sector(cache));
	ocf_metadata_remove_from_collision(cache, cline, part_id);
	ocf_metadata_end_collision_shared_access(
			cache, cline);

	core = ocf_cache_get_core(cache, core_id);
	env_atomic_dec(&core->runtime_meta->cached_clines);
	env_atomic_dec(&core->runtime_meta->
			part_counters[part_id].cached_clines);
}

/* the caller must hold the metadata lock */
uint32_t evp_lru_req_clines(struct ocf_request *req,
	struct ocf_part_runtime *part, ocf_part_id_t part_id,
	uint32_t cline_no)
{
	struct ocf_lru_iter iter;
	uint32_t i;
	ocf_cache_line_t cline;
	uint64_t core_line;
	ocf_core_id_t core_id;
	ocf_cache_t cache = req->cache;
	unsigned evp;
	unsigned req_idx = 0;
	ocf_part_id_t dst_part_id = req->part_id;
	struct ocf_part_runtime *dst_part = cache->user_parts[dst_part_id].
			runtime;

	if (cline_no == 0)
		return 0;

	if (unlikely(ocf_engine_unmapped_count(req) < cline_no)) {
		ocf_cache_log(req->cache, log_err, "Not enough space in"
				"request: unmapped %u, requested %u",
				ocf_engine_unmapped_count(req),
				cline_no);
		ENV_BUG();
	}

	evp = req->io_queue->eviction_idx++ % OCF_NUM_EVICTION_LISTS;

	lru_iter_eviction_init(&iter, cache, part, part_id, evp, req);

	i = 0;
	while (i < cline_no) {
		if (!evp_lru_can_evict(cache))
			break;

		if (part_id != PARTITION_INVALID) {
			cline = lru_iter_eviction_next(&iter, dst_part,
				dst_part_id, &core_id, &core_line);
		} else {
			cline = lru_iter_free_next(&iter, dst_part, dst_part_id);
		}

		if (cline == end_marker)
			break;

		ENV_BUG_ON(metadata_test_dirty(cache, cline));

		/* TODO: if atomic mode is restored, need to zero metadata
		 * before proceeding with cleaning (see version <= 20.12) */

		/* find next unmapped cacheline in request */
		while (req_idx + 1 < req->core_line_count &&
				req->map[req_idx].status != LOOKUP_MISS) {
			req_idx++;
		}

		ENV_BUG_ON(req->map[req_idx].status != LOOKUP_MISS);

		if (part_id != PARTITION_INVALID) {
			evp_lru_invalidate(cache, cline, core_id, part_id);
			_lru_unlock_hash(&iter, core_id, core_line);
		}

		ocf_map_cache_line(req, req_idx, cline);

		req->map[req_idx].status = LOOKUP_REMAPPED;
		ocf_engine_patch_req_info(cache, req, req_idx);
		req->map[req_idx].wr_locked = true;

		++req_idx;
		++i;
		/* Number of cachelines to evict have to match space in the
		 * request */
		ENV_BUG_ON(req_idx == req->core_line_count && i != cline_no );
	}

	return i;
}

/* the caller must hold the metadata lock */
void evp_lru_hot_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	const uint32_t ev_list = (cline % OCF_NUM_EVICTION_LISTS);
	struct lru_eviction_policy_meta *node;
	struct ocf_lru_list *list;
	ocf_part_id_t part_id;
	struct ocf_part_runtime *part;
	bool hot;
	bool clean;

	node = ocf_get_lru(cache, cline);

	OCF_METADATA_EVICTION_RD_LOCK(cline);
	hot = node->hot;
	OCF_METADATA_EVICTION_RD_UNLOCK(cline);

	if (hot)
		return;

	part_id = ocf_metadata_get_partition_id(cache, cline);
	part = cache->user_parts[part_id].runtime;
	clean = !metadata_test_dirty(cache, cline);
	list = evp_lru_get_list(part, ev_list, clean);

	OCF_METADATA_EVICTION_WR_LOCK(cline);

	/* cacheline must be on the list when set_hot gets called */
	ENV_BUG_ON(node->next == end_marker && list->tail != cline);
	ENV_BUG_ON(node->next == end_marker && list->tail != cline);

	evp_lru_set_hot(cache, list, part_id, clean, cline);

	OCF_METADATA_EVICTION_WR_UNLOCK(cline);
}

static inline void _lru_init(struct ocf_lru_list *list)
{
	list->num_nodes = 0;
	list->head = end_marker;
	list->tail = end_marker;
	list->num_hot = 0;
	list->last_hot = end_marker;
}

void evp_lru_init_evp(ocf_cache_t cache, struct ocf_part_runtime *part)
{
	struct ocf_lru_list *clean_list;
	struct ocf_lru_list *dirty_list;
	uint32_t i;

	for (i = 0; i < OCF_NUM_EVICTION_LISTS; i++) {
		clean_list = evp_lru_get_list(part, i, true);
		dirty_list = evp_lru_get_list(part, i, false);

		_lru_init(clean_list);
		_lru_init(dirty_list);
	}

	env_atomic_set(&part->curr_size, 0);
}

void evp_lru_clean_cline(ocf_cache_t cache, uint32_t cline)
{
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache, cline);
	struct ocf_user_part *part = &cache->user_parts[part_id];
	uint32_t ev_list = (cline % OCF_NUM_EVICTION_LISTS);
	struct ocf_lru_list *clean_list;
	struct ocf_lru_list *dirty_list;

	clean_list = evp_lru_get_list(part->runtime, ev_list, true);
	dirty_list = evp_lru_get_list(part->runtime, ev_list, false);

	OCF_METADATA_EVICTION_WR_LOCK(cline);

	remove_lru_list(cache, dirty_list, part_id, true, cline);
	add_lru_head(cache, clean_list, part_id, false, cline);

	OCF_METADATA_EVICTION_WR_UNLOCK(cline);
}

void evp_lru_dirty_cline(ocf_cache_t cache, uint32_t cline)
{
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache, cline);
	struct ocf_user_part *part = &cache->user_parts[part_id];
	uint32_t ev_list = (cline % OCF_NUM_EVICTION_LISTS);
	struct ocf_lru_list *clean_list;
	struct ocf_lru_list *dirty_list;

	clean_list = evp_lru_get_list(part->runtime, ev_list, true);
	dirty_list = evp_lru_get_list(part->runtime, ev_list, false);

	OCF_METADATA_EVICTION_WR_LOCK(cline);

	remove_lru_list(cache, clean_list, part_id, false, cline);
	add_lru_head(cache, dirty_list, part_id, true, cline);

	OCF_METADATA_EVICTION_WR_UNLOCK(cline);
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
	while (metadata_test_valid_any(cache, lg) &&
			phys +  1 < collision_table_entries) {
		++phys;

		if (phys == collision_table_entries)
			break;

		lg = ocf_metadata_map_phy2lg(cache, phys);
	}

	return phys;
}

/* put invalid cachelines at the end of LRU  */
void ocf_lru_populate(ocf_cache_t cache, ocf_cache_line_t num_free_clines)
{
	ocf_cache_line_t phys, cline;
	ocf_cache_line_t collision_table_entries =
			ocf_metadata_collision_table_entries(cache);
	struct ocf_lru_list *list;
	unsigned ev_list;
	unsigned i;

	evp_lru_init_evp(cache, cache->free);

	phys = 0;
	for (i = 0; i < num_free_clines; i++) {
		/* find first invalid cacheline */
		phys = next_phys_invalid(cache, phys);
		ENV_BUG_ON(phys == collision_table_entries);
		cline = ocf_metadata_map_phy2lg(cache, phys);
		++phys;

		ocf_metadata_set_partition_id(cache, cline, PARTITION_INVALID);

		ev_list = (cline % OCF_NUM_EVICTION_LISTS);
		list = evp_lru_get_list(cache->free, ev_list, true);

		add_lru_head(cache, list, PARTITION_INVALID, true, cline);
	}

	/* we should have reached the last invalid cache line */
	phys = next_phys_invalid(cache, phys);
	ENV_BUG_ON(phys != collision_table_entries);

	env_atomic_set(&cache->free->curr_size, num_free_clines);
}

static bool _is_cache_line_acting(struct ocf_cache *cache,
		uint32_t cache_line, ocf_core_id_t core_id,
		uint64_t start_line, uint64_t end_line)
{
	ocf_core_id_t tmp_core_id;
	uint64_t core_line;

	ocf_metadata_get_core_info(cache, cache_line,
		&tmp_core_id, &core_line);

	if (core_id != OCF_CORE_ID_INVALID) {
		if (core_id != tmp_core_id)
			return false;

		if (core_line < start_line || core_line > end_line)
			return false;

	} else if (tmp_core_id == OCF_CORE_ID_INVALID) {
		return false;
	}

	return true;
}

/*
 * Iterates over cache lines that belong to the core device with
 * core ID = core_id  whose core byte addresses are in the range
 * [start_byte, end_byte] and applies actor(cache, cache_line) to all
 * matching cache lines
 *
 * set partition_id to PARTITION_INVALID to not care about partition_id
 *
 * global metadata write lock must be held before calling this function
 */
int ocf_metadata_actor(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_core_id_t core_id,
		uint64_t start_byte, uint64_t end_byte,
		ocf_metadata_actor_t actor)
{
	uint32_t step = 0;
	uint64_t start_line, end_line;
	int ret = 0;
	struct ocf_alock *c = ocf_cache_line_concurrency(cache);
	int clean;
	struct ocf_lru_list *list;
	struct ocf_part_runtime *part;
	unsigned i, cline;
	struct lru_eviction_policy_meta *node;

	start_line = ocf_bytes_2_lines(cache, start_byte);
	end_line = ocf_bytes_2_lines(cache, end_byte);

	if (part_id == PARTITION_INVALID) {
		for (cline = 0; cline < cache->device->collision_table_entries;
				++cline) {
			if (_is_cache_line_acting(cache, cline, core_id,
					start_line, end_line)) {
				if (ocf_cache_line_is_used(c, cline))
					ret = -OCF_ERR_AGAIN;
				else
					actor(cache, cline);
			}

			OCF_COND_RESCHED_DEFAULT(step);
		}
		return ret;
	}

	part = cache->user_parts[part_id].runtime;
	for (i = 0; i < OCF_NUM_EVICTION_LISTS; i++) {
		for (clean = 0; clean <= 1; clean++) {
			list = evp_lru_get_list(part, i, clean);

			cline = list->tail;
			while (cline != end_marker) {
				node = ocf_get_lru(cache, cline);
				if (!_is_cache_line_acting(cache, cline,
						core_id, start_line,
						end_line)) {
					cline = node->prev;
					continue;
				}
				if (ocf_cache_line_is_used(c, cline))
					ret = -OCF_ERR_AGAIN;
				else
					actor(cache, cline);
				cline = node->prev;
				OCF_COND_RESCHED_DEFAULT(step);
			}
		}
	}

	return ret;
}

uint32_t ocf_lru_num_free(ocf_cache_t cache)
{
	return env_atomic_read(&cache->free->curr_size);
}
