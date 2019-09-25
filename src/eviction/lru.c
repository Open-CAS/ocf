/*
 * Copyright(c) 2012-2018 Intel Corporation
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

/* -- Start of LRU functions --*/

/* Returns 1 if the given collision_index is the _head_ of
 * the LRU list, 0 otherwise.
 */
/* static inline int is_lru_head(unsigned collision_index) {
 *	return collision_index == lru_list.lru_head;
 * }
 */

#define is_lru_head(x) (x == collision_table_entries)
#define is_lru_tail(x) (x == collision_table_entries)

/* Sets the given collision_index as the new _head_ of the LRU list. */
static inline void update_lru_head(ocf_cache_t cache,
		int partition_id, unsigned int collision_index,
		int cline_dirty)
{
	struct ocf_user_part *part = &cache->user_parts[partition_id];


	if (cline_dirty)
		part->runtime->eviction.policy.lru.dirty_head = collision_index;
	else
		part->runtime->eviction.policy.lru.clean_head = collision_index;
}

/* Sets the given collision_index as the new _tail_ of the LRU list. */
static inline void update_lru_tail(ocf_cache_t cache,
		int partition_id, unsigned int collision_index,
		int cline_dirty)
{
	struct ocf_user_part *part = &cache->user_parts[partition_id];

	if (cline_dirty)
		part->runtime->eviction.policy.lru.dirty_tail = collision_index;
	else
		part->runtime->eviction.policy.lru.clean_tail = collision_index;
}

/* Sets the given collision_index as the new _head_ and _tail_ of
 * the LRU list.
 */
static inline void update_lru_head_tail(ocf_cache_t cache,
		int partition_id, unsigned int collision_index, int cline_dirty)
{
	update_lru_head(cache, partition_id, collision_index, cline_dirty);
	update_lru_tail(cache, partition_id, collision_index, cline_dirty);
}

/* Adds the given collision_index to the _head_ of the LRU list */
static void add_lru_head(ocf_cache_t cache, int partition_id,
		unsigned int collision_index, int cline_dirty)
{
	unsigned int curr_head_index;
	unsigned int collision_table_entries =
			cache->device->collision_table_entries;
	struct ocf_user_part *part = &cache->user_parts[partition_id];
	union eviction_policy_meta eviction;

	ENV_BUG_ON(!(collision_index < collision_table_entries));

	ocf_metadata_get_evicition_policy(cache, collision_index, &eviction);

	/* First node to be added/ */
	if ((cline_dirty && !part->runtime->eviction.policy.lru.has_dirty_nodes) ||
	    (!cline_dirty && !part->runtime->eviction.policy.lru.has_clean_nodes)) {
		update_lru_head_tail(cache, partition_id, collision_index, cline_dirty);

		eviction.lru.next = collision_table_entries;
		eviction.lru.prev = collision_table_entries;

		if (cline_dirty)
			part->runtime->eviction.policy.lru.has_dirty_nodes = 1;
		else
			part->runtime->eviction.policy.lru.has_clean_nodes = 1;

		ocf_metadata_set_evicition_policy(cache, collision_index,
				&eviction);
	} else {
		union eviction_policy_meta eviction_curr;

		/* Not the first node to be added. */
		curr_head_index = cline_dirty ?
				part->runtime->eviction.policy.lru.dirty_head :
				part->runtime->eviction.policy.lru.clean_head;

		ENV_BUG_ON(!(curr_head_index < collision_table_entries));

		ocf_metadata_get_evicition_policy(cache, curr_head_index,
						&eviction_curr);

		eviction.lru.next = curr_head_index;
		eviction.lru.prev = collision_table_entries;
		eviction_curr.lru.prev = collision_index;

		update_lru_head(cache, partition_id, collision_index, cline_dirty);

		ocf_metadata_set_evicition_policy(cache, curr_head_index,
				&eviction_curr);
		ocf_metadata_set_evicition_policy(cache, collision_index,
				&eviction);
	}
}

/* Deletes the node with the given collision_index from the lru list */
static void remove_lru_list(ocf_cache_t cache, int partition_id,
		unsigned int collision_index, int cline_dirty)
{
	int is_clean_head = 0, is_clean_tail = 0, is_dirty_head = 0, is_dirty_tail = 0;
	uint32_t prev_lru_node, next_lru_node;
	uint32_t collision_table_entries = cache->device->collision_table_entries;
	struct ocf_user_part *part = &cache->user_parts[partition_id];
	union eviction_policy_meta eviction;

	ENV_BUG_ON(!(collision_index < collision_table_entries));

	ocf_metadata_get_evicition_policy(cache, collision_index, &eviction);

	/* Find out if this node is LRU _head_ or LRU _tail_ */
	if (part->runtime->eviction.policy.lru.clean_head == collision_index)
		is_clean_head = 1;
	if (part->runtime->eviction.policy.lru.dirty_head == collision_index)
		is_dirty_head = 1;
	if (part->runtime->eviction.policy.lru.clean_tail == collision_index)
		is_clean_tail = 1;
	if (part->runtime->eviction.policy.lru.dirty_tail == collision_index)
		is_dirty_tail = 1;
	ENV_BUG_ON((is_clean_tail || is_clean_head) && (is_dirty_tail || is_dirty_head));

	/* Set prev and next (even if not existent) */
	next_lru_node = eviction.lru.next;
	prev_lru_node = eviction.lru.prev;

	/* Case 1: If we are head AND tail, there is only one node.
	 * So unlink node and set that there is no node left in the list.
	 */
	if ((is_clean_head && is_clean_tail) || (is_dirty_head && is_dirty_tail)) {
		eviction.lru.next = collision_table_entries;
		eviction.lru.prev = collision_table_entries;

		update_lru_head_tail(cache, partition_id, collision_table_entries, cline_dirty);

		if (cline_dirty)
			part->runtime->eviction.policy.lru.has_dirty_nodes = 0;
		else
			 part->runtime->eviction.policy.lru.has_clean_nodes = 0;

		ocf_metadata_set_evicition_policy(cache, collision_index,
				&eviction);

		update_lru_head_tail(cache, partition_id,
				collision_table_entries, cline_dirty);
	}

	/* Case 2: else if this collision_index is LRU head, but not tail,
	 * update head and return
	 */
	else if ((!is_clean_tail && is_clean_head) || (!is_dirty_tail && is_dirty_head)) {
		union eviction_policy_meta eviction_next;

		ENV_BUG_ON(!(next_lru_node < collision_table_entries));

		ocf_metadata_get_evicition_policy(cache, next_lru_node,
				&eviction_next);

		update_lru_head(cache, partition_id, next_lru_node, cline_dirty);

		eviction.lru.next = collision_table_entries;
		eviction_next.lru.prev = collision_table_entries;

		ocf_metadata_set_evicition_policy(cache, collision_index,
				&eviction);

		ocf_metadata_set_evicition_policy(cache, next_lru_node,
				&eviction_next);
	}

	/* Case 3: else if this collision_index is LRU tail, but not head,
	 * update tail and return
	 */
	else if ((is_clean_tail && !is_clean_head) || (is_dirty_tail && !is_dirty_head)) {
		union eviction_policy_meta eviction_prev;

		ENV_BUG_ON(!(prev_lru_node < collision_table_entries));

		update_lru_tail(cache, partition_id, prev_lru_node, cline_dirty);

		ocf_metadata_get_evicition_policy(cache, prev_lru_node,
				&eviction_prev);

		eviction.lru.prev = collision_table_entries;
		eviction_prev.lru.next = collision_table_entries;

		ocf_metadata_set_evicition_policy(cache, collision_index,
				&eviction);

		ocf_metadata_set_evicition_policy(cache, prev_lru_node,
				&eviction_prev);
	}

	/* Case 4: else this collision_index is a middle node. There is no
	 * change to the head and the tail pointers.
	 */
	else {
		union eviction_policy_meta eviction_prev;
		union eviction_policy_meta eviction_next;

		ENV_BUG_ON(!(next_lru_node < collision_table_entries));
		ENV_BUG_ON(!(prev_lru_node < collision_table_entries));

		ocf_metadata_get_evicition_policy(cache, next_lru_node,
				&eviction_next);
		ocf_metadata_get_evicition_policy(cache, prev_lru_node,
				&eviction_prev);

		/* Update prev and next nodes */
		eviction_prev.lru.next = eviction.lru.next;
		eviction_next.lru.prev = eviction.lru.prev;

		/* Update the given node */
		eviction.lru.next = collision_table_entries;
		eviction.lru.prev = collision_table_entries;

		ocf_metadata_set_evicition_policy(cache, collision_index,
				&eviction);
		ocf_metadata_set_evicition_policy(cache, next_lru_node,
				&eviction_next);
		ocf_metadata_set_evicition_policy(cache, prev_lru_node,
				&eviction_prev);
	}
}

/*-- End of LRU functions*/

void evp_lru_init_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	union eviction_policy_meta eviction;

	ocf_metadata_get_evicition_policy(cache, cline, &eviction);

	eviction.lru.prev = cache->device->collision_table_entries;
	eviction.lru.next = cache->device->collision_table_entries;

	ocf_metadata_set_evicition_policy(cache, cline, &eviction);
}


/* the caller must hold the metadata lock */
void evp_lru_rm_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache, cline);

	remove_lru_list(cache, part_id, cline, metadata_test_dirty(cache, cline));
}

static void evp_lru_clean_end(void *private_data, int error)
{
	struct ocf_refcnt *counter = private_data;

	ocf_refcnt_dec(counter);
}

static int evp_lru_clean_getter(ocf_cache_t cache,
		void *getter_context, uint32_t item, ocf_cache_line_t *line)
{
	union eviction_policy_meta eviction;
	struct ocf_cleaner_attribs *attribs = getter_context;
	ocf_cache_line_t prev_cline, curr_cline = attribs->getter_item;

	while (curr_cline < cache->device->collision_table_entries) {
		ocf_metadata_get_evicition_policy(cache, curr_cline,
				&eviction);
		prev_cline = eviction.lru.prev;

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
		.getter_item = part->runtime->eviction.policy.lru.dirty_tail,

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
	union eviction_policy_meta eviction;

	if (cline_no == 0)
		return 0;

	i =  0;
	curr_cline = part->runtime->eviction.policy.lru.clean_tail;
	/* Find cachelines to be evicted. */
	while (i < cline_no) {
		ENV_BUG_ON(curr_cline > cache->device->collision_table_entries);

		if (!evp_lru_can_evict(cache))
			break;

		if (curr_cline == cache->device->collision_table_entries)
			break;

		ocf_metadata_get_evicition_policy(cache, curr_cline,
				&eviction);
		prev_cline = eviction.lru.prev;

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

	if (i < cline_no && part->runtime->eviction.policy.lru.dirty_tail !=
			cache->device->collision_table_entries) {
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

	uint32_t prev_lru_node, next_lru_node;
	uint32_t collision_table_entries = cache->device->collision_table_entries;
	union eviction_policy_meta eviction;

	int cline_dirty;

	ocf_metadata_get_evicition_policy(cache, cline, &eviction);

	next_lru_node = eviction.lru.next;
	prev_lru_node = eviction.lru.prev;

	cline_dirty = metadata_test_dirty(cache, cline);

	if ((next_lru_node != collision_table_entries) ||
	    (prev_lru_node != collision_table_entries) ||
	    ((part->runtime->eviction.policy.lru.clean_head == cline) &&
	     (part->runtime->eviction.policy.lru.clean_tail == cline)) ||
	    ((part->runtime->eviction.policy.lru.dirty_head == cline) &&
	     (part->runtime->eviction.policy.lru.dirty_tail == cline))) {
		remove_lru_list(cache, part_id, cline, cline_dirty);
	}

	/* Update LRU */
	add_lru_head(cache, part_id, cline, cline_dirty);
}

void evp_lru_init_evp(ocf_cache_t cache, ocf_part_id_t part_id)
{
	unsigned int collision_table_entries =
			cache->device->collision_table_entries;
	struct ocf_user_part *part = &cache->user_parts[part_id];

	part->runtime->eviction.policy.lru.has_clean_nodes = 0;
	part->runtime->eviction.policy.lru.has_dirty_nodes = 0;
	part->runtime->eviction.policy.lru.clean_head = collision_table_entries;
	part->runtime->eviction.policy.lru.clean_tail = collision_table_entries;
	part->runtime->eviction.policy.lru.dirty_head = collision_table_entries;
	part->runtime->eviction.policy.lru.dirty_tail = collision_table_entries;
}

void evp_lru_clean_cline(ocf_cache_t cache, ocf_part_id_t part_id,
		uint32_t cline)
{
	OCF_METADATA_EVICTION_LOCK();
	remove_lru_list(cache, part_id, cline, 1);
	add_lru_head(cache, part_id, cline, 0);
	OCF_METADATA_EVICTION_UNLOCK();
}

void evp_lru_dirty_cline(ocf_cache_t cache, ocf_part_id_t part_id,
		uint32_t cline)
{
	OCF_METADATA_EVICTION_LOCK();
	remove_lru_list(cache, part_id, cline, 0);
	add_lru_head(cache, part_id, cline, 1);
	OCF_METADATA_EVICTION_UNLOCK();
}

