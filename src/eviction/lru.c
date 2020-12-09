/*
 * Copyright(c) 2012-2020 Intel Corporation
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
#include "../ocf_request.h"

#define OCF_EVICTION_MAX_SCAN 1024

static const ocf_cache_line_t end_marker = (ocf_cache_line_t)-1;

/* Adds the given collision_index to the _head_ of the LRU list */
static void add_lru_head(ocf_cache_t cache,
		struct ocf_lru_list *list,
		unsigned int collision_index)

{
	struct lru_eviction_policy_meta *node;
	unsigned int curr_head_index;

	ENV_BUG_ON(collision_index == end_marker);

	node = &ocf_metadata_get_eviction_policy(cache, collision_index)->lru;

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

		curr_head = &ocf_metadata_get_eviction_policy(cache,
				curr_head_index)->lru;

		node->next = curr_head_index;
		node->prev = end_marker;
		curr_head->prev = collision_index;

		list->head = collision_index;

		++list->num_nodes;
	}
}

/* Deletes the node with the given collision_index from the lru list */
static void remove_lru_list(ocf_cache_t cache,
		struct ocf_lru_list *list,
		unsigned int collision_index)
{
	int is_head = 0, is_tail = 0;
	uint32_t prev_lru_node, next_lru_node;
	struct lru_eviction_policy_meta *node;

	ENV_BUG_ON(collision_index == end_marker);

	node = &ocf_metadata_get_eviction_policy(cache, collision_index)->lru;

	is_head = (list->head == collision_index);
	is_tail = (list->tail == collision_index);

	/* Set prev and next (even if not existent) */
	next_lru_node = node->next;
	prev_lru_node = node->prev;

	/* Case 1: If we are head AND tail, there is only one node.
	 * So unlink node and set that there is no node left in the list.
	 */
	if (is_head && is_tail) {
		node->next = end_marker;
		node->prev = end_marker;

		list->head = end_marker;
		list->tail = end_marker;
	}

	/* Case 2: else if this collision_index is LRU head, but not tail,
	 * update head and return
	 */
	else if (is_head) {
		struct lru_eviction_policy_meta *next_node;

		ENV_BUG_ON(next_lru_node == end_marker);

		next_node = &ocf_metadata_get_eviction_policy(cache,
				next_lru_node)->lru;

		list->head = next_lru_node;
		node->next = end_marker;
		next_node->prev = end_marker;
	}

	/* Case 3: else if this collision_index is LRU tail, but not head,
	 * update tail and return
	 */
	else if (is_tail) {
		struct lru_eviction_policy_meta *prev_node;

		ENV_BUG_ON(prev_lru_node == end_marker);

		list->tail = prev_lru_node;

		prev_node = &ocf_metadata_get_eviction_policy(cache,
				prev_lru_node)->lru;

		node->prev = end_marker;
		prev_node->next = end_marker;
	}

	/* Case 4: else this collision_index is a middle node. There is no
	 * change to the head and the tail pointers.
	 */
	else {
		struct lru_eviction_policy_meta *prev_node;
		struct lru_eviction_policy_meta *next_node;

		ENV_BUG_ON(next_lru_node == end_marker);
		ENV_BUG_ON(prev_lru_node == end_marker);

		next_node = &ocf_metadata_get_eviction_policy(cache,
				next_lru_node)->lru;
		prev_node = &ocf_metadata_get_eviction_policy(cache,
				prev_lru_node)->lru;

		/* Update prev and next nodes */
		prev_node->next = node->next;
		next_node->prev = node->prev;

		/* Update the given node */
		node->next = end_marker;
		node->prev = end_marker;
	}

	--list->num_nodes;
}

/*-- End of LRU functions*/

void evp_lru_init_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	struct lru_eviction_policy_meta *node;

	node = &ocf_metadata_get_eviction_policy(cache, cline)->lru;

	node->prev = end_marker;
	node->next = end_marker;
}


/* the caller must hold the metadata lock */
void evp_lru_rm_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache, cline);
	struct ocf_user_part *part = &cache->user_parts[part_id];
	struct ocf_lru_list *list;

	list = metadata_test_dirty(cache, cline) ?
		&part->runtime->eviction.policy.lru.dirty :
		&part->runtime->eviction.policy.lru.clean;

	remove_lru_list(cache, list, cline);
}

static void evp_lru_clean_end(void *private_data, int error)
{
	struct ocf_refcnt *counter = private_data;

	ocf_refcnt_dec(counter);
}

static int evp_lru_clean_getter(ocf_cache_t cache,
		void *getter_context, uint32_t item, ocf_cache_line_t *line)
{
	struct ocf_cleaner_attribs *attribs = getter_context;
	ocf_cache_line_t prev_cline, curr_cline = attribs->getter_item;

	while (curr_cline != end_marker) {
		prev_cline = ocf_metadata_get_eviction_policy(cache,
				curr_cline)->lru.prev;

		/* Prevent evicting already locked items */
		if (ocf_cache_line_is_used(cache, curr_cline)) {
			curr_cline = prev_cline;
			continue;
		}

		ENV_BUG_ON(!metadata_test_dirty(cache, curr_cline));

		*line = curr_cline;
		attribs->getter_item = prev_cline;
		return 0;
	}

	return -1;
}

static void evp_lru_clean(ocf_cache_t cache, ocf_queue_t io_queue,
		ocf_part_id_t part_id, uint32_t count)
{
	struct ocf_refcnt *counter = &cache->refcnt.cleaning[part_id];
	struct ocf_user_part *part = &cache->user_parts[part_id];
	struct ocf_cleaner_attribs attribs = {
		.cache_line_lock = true,
		.do_sort = true,

		.cmpl_context = counter,
		.cmpl_fn = evp_lru_clean_end,

		.getter = evp_lru_clean_getter,
		.getter_context = &attribs,
		.getter_item = part->runtime->eviction.policy.lru.dirty.tail,

		.count = count > 32 ? 32 : count,

		.io_queue = io_queue
	};
	int cnt;

	if (ocf_mngt_cache_is_locked(cache))
		return;

	cnt = ocf_refcnt_inc(counter);
	if (!cnt) {
		/* cleaner disabled by management operation */
		return;
	}
	if (cnt > 1) {
		/* cleaning already running for this partition */
		ocf_refcnt_dec(counter);
		return;
	}

	ocf_cleaner_fire(cache, &attribs);
}

static void evp_lru_zero_line_complete(struct ocf_request *ocf_req, int error)
{
	env_atomic_dec(&ocf_req->cache->pending_eviction_clines);
}

static void evp_lru_zero_line(ocf_cache_t cache, ocf_queue_t io_queue,
		ocf_cache_line_t line)
{
	struct ocf_request *req;
	ocf_core_id_t id;
	uint64_t addr, core_line;

	ocf_metadata_get_core_info(cache, line, &id, &core_line);
	addr = core_line * ocf_line_size(cache);

	req = ocf_req_new(io_queue, &cache->core[id], addr,
			ocf_line_size(cache), OCF_WRITE);
	if (!req)
		return;

	if (req->d2c) {
		/* cache device is being detached */
		ocf_req_put(req);
		return;
	}

	req->info.internal = true;
	req->complete = evp_lru_zero_line_complete;

	env_atomic_inc(&cache->pending_eviction_clines);

	ocf_engine_zero_line(req);
}

bool evp_lru_can_evict(ocf_cache_t cache)
{
	if (env_atomic_read(&cache->pending_eviction_clines) >=
			OCF_PENDING_EVICTION_LIMIT) {
		return false;
	}

	return true;
}

/* the caller must hold the metadata lock */
uint32_t evp_lru_req_clines(ocf_cache_t cache, ocf_queue_t io_queue,
		ocf_part_id_t part_id, uint32_t cline_no)
{
	uint32_t i;
	ocf_cache_line_t curr_cline, prev_cline;
	struct ocf_user_part *part = &cache->user_parts[part_id];

	if (cline_no == 0)
		return 0;

	i =  0;
	curr_cline = part->runtime->eviction.policy.lru.clean.tail;
	/* Find cachelines to be evicted. */
	while (i < cline_no) {
		if (!evp_lru_can_evict(cache))
			break;

		if (curr_cline == end_marker)
			break;

		prev_cline = ocf_metadata_get_eviction_policy(cache,
				curr_cline)->lru.prev;

		/* Prevent evicting already locked items */
		if (ocf_cache_line_is_used(cache, curr_cline)) {
			curr_cline = prev_cline;
			continue;
		}

		ENV_BUG_ON(metadata_test_dirty(cache, curr_cline));

		if (ocf_volume_is_atomic(&cache->device->volume)) {
			/* atomic cache, we have to trim cache lines before
			 * eviction
			 */
			evp_lru_zero_line(cache, io_queue, curr_cline);

		} else {
			ocf_metadata_start_collision_shared_access(cache,
					curr_cline);
			set_cache_line_invalid_no_flush(cache, 0,
					ocf_line_end_sector(cache),
					curr_cline);
			ocf_metadata_end_collision_shared_access(cache,
					curr_cline);

			/* Goto next item. */
			i++;
		}

		curr_cline = prev_cline;
	}

	if (i < cline_no && part->runtime->eviction.policy.lru.dirty.tail !=
			end_marker) {
		evp_lru_clean(cache, io_queue, part_id, cline_no - i);
	}

	/* Return number of clines that were really evicted */
	return i;
}

/* the caller must hold the metadata lock */
void evp_lru_hot_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache, cline);
	struct ocf_user_part *part = &cache->user_parts[part_id];
	struct lru_eviction_policy_meta *node;
	int cline_dirty;
	struct ocf_lru_list *list;

	node = &ocf_metadata_get_eviction_policy(cache, cline)->lru;

	cline_dirty = metadata_test_dirty(cache, cline);
	list = cline_dirty ?
		&part->runtime->eviction.policy.lru.dirty :
		&part->runtime->eviction.policy.lru.clean;

	if (node->next != end_marker ||
			node->prev != end_marker ||
			list->head == cline || list->tail == cline) {
		remove_lru_list(cache, list, cline);
	}

	/* Update LRU */
	add_lru_head(cache, list, cline);
}

static inline void _lru_init(struct ocf_lru_list *list)
{
	list->num_nodes = 0;
	list->head = end_marker;
	list->tail = end_marker;
}

void evp_lru_init_evp(ocf_cache_t cache, ocf_part_id_t part_id)
{
	struct ocf_user_part *part = &cache->user_parts[part_id];
	struct ocf_lru_list *clean_list;
	struct ocf_lru_list *dirty_list;

	clean_list = &part->runtime->eviction.policy.lru.clean;
	dirty_list = &part->runtime->eviction.policy.lru.dirty;

	_lru_init(clean_list);
	_lru_init(dirty_list);
}

void evp_lru_clean_cline(ocf_cache_t cache, ocf_part_id_t part_id,
		uint32_t cline)
{
	struct ocf_user_part *part = &cache->user_parts[part_id];
	struct ocf_lru_list *clean_list;
	struct ocf_lru_list *dirty_list;

	clean_list = &part->runtime->eviction.policy.lru.clean;
	dirty_list = &part->runtime->eviction.policy.lru.dirty;

	OCF_METADATA_EVICTION_LOCK();
	remove_lru_list(cache, dirty_list, cline);
	add_lru_head(cache, clean_list, cline);
	OCF_METADATA_EVICTION_UNLOCK();
}

void evp_lru_dirty_cline(ocf_cache_t cache, ocf_part_id_t part_id,
		uint32_t cline)
{
	struct ocf_user_part *part = &cache->user_parts[part_id];
	struct ocf_lru_list *clean_list;
	struct ocf_lru_list *dirty_list;

	clean_list = &part->runtime->eviction.policy.lru.clean;
	dirty_list = &part->runtime->eviction.policy.lru.dirty;

	OCF_METADATA_EVICTION_LOCK();
	remove_lru_list(cache, clean_list, cline);
	add_lru_head(cache, dirty_list, cline);
	OCF_METADATA_EVICTION_UNLOCK();
}

