/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_priv.h"
#include "../ocf_cache_priv.h"
#include "../ocf_queue_priv.h"
#include "engine_common.h"
#define OCF_ENGINE_DEBUG_IO_NAME "common"
#include "engine_debug.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_cleaner.h"
#include "../metadata/metadata.h"
#include "../layer_space_management.h"

void ocf_engine_error(struct ocf_request *rq,
		bool stop_cache, const char *msg)
{
	struct ocf_cache *cache = rq->cache;

	if (stop_cache)
		env_bit_clear(ocf_cache_state_running, &cache->cache_state);

	ocf_core_log(&cache->core_obj[rq->core_id], log_err,
			"%s sector: %" ENV_PRIu64 ", bytes: %u\n", msg,
			BYTES_TO_SECTORS(rq->byte_position), rq->byte_length);
}

void ocf_engine_lookup_map_entry(struct ocf_cache *cache,
		struct ocf_map_info *entry, ocf_core_id_t core_id,
		uint64_t core_line)
{
	ocf_cache_line_t line;
	ocf_cache_line_t hash_key;

	hash_key = ocf_metadata_hash_func(cache, core_line, core_id);

	/* Initially assume that we have cache miss.
	 * Hash points to proper bucket.
	 */
	entry->hash_key = hash_key;
	entry->status = LOOKUP_MISS;
	entry->coll_idx = cache->device->collision_table_entries;
	entry->core_line = core_line;

	line = ocf_metadata_get_hash(cache, hash_key);

	while (line != cache->device->collision_table_entries) {
		ocf_core_id_t curr_core_id;
		uint64_t curr_core_line;

		ocf_metadata_get_core_info(cache, line, &curr_core_id,
				&curr_core_line);

		if (core_id == curr_core_id && curr_core_line == core_line) {
			entry->coll_idx = line;
			entry->status = LOOKUP_HIT;
			break;
		}

		line = ocf_metadata_get_collision_next(cache, line);
	}
}

static inline int _ocf_engine_check_map_entry(struct ocf_cache *cache,
		struct ocf_map_info *entry, ocf_core_id_t core_id)
{
	ocf_core_id_t _core_id;
	uint64_t _core_line;

	if (entry->status == LOOKUP_MISS)
		return 0;

	ENV_BUG_ON(entry->coll_idx >= cache->device->collision_table_entries);

	ocf_metadata_get_core_info(cache, entry->coll_idx, &_core_id,
			&_core_line);

	if (core_id == _core_id && _core_line == entry->core_line)
		return 0;
	else
		return -1;
}

void ocf_engine_update_rq_info(struct ocf_cache *cache,
		struct ocf_request *rq, uint32_t entry)
{
	uint8_t start_sector = 0;
	uint8_t end_sector = ocf_line_end_sector(cache);
	struct ocf_map_info *_entry = &(rq->map[entry]);

	if (entry == 0) {
		start_sector = BYTES_TO_SECTORS(rq->byte_position)
				% ocf_line_sectors(cache);
	}

	if (entry == rq->core_line_count - 1) {
		end_sector = BYTES_TO_SECTORS(rq->byte_position +
				rq->byte_length - 1)% ocf_line_sectors(cache);
	}

	/* Handle return value */
	switch (_entry->status) {
	case LOOKUP_HIT:
		if (metadata_test_valid_sec(cache, _entry->coll_idx,
				start_sector, end_sector)) {
			rq->info.hit_no++;
		} else {
			rq->info.invalid_no++;
		}

		/* Check request is dirty */
		if (metadata_test_dirty(cache, _entry->coll_idx)) {
			rq->info.dirty_any++;

			/* Check if cache line is fully dirty */
			if (metadata_test_dirty_all(cache, _entry->coll_idx))
				rq->info.dirty_all++;
		}

		if (rq->part_id != ocf_metadata_get_partition_id(cache,
				_entry->coll_idx)) {
			/*
			 * Need to move this cache line into other partition
			 */
			_entry->re_part = rq->info.re_part = true;
		}

		break;
	case LOOKUP_MISS:
		rq->info.seq_req = false;
		break;
	case LOOKUP_MAPPED:
		break;
	default:
		ENV_BUG();
		break;
	}

	/* Check if cache hit is sequential */
	if (rq->info.seq_req && entry) {
		if (ocf_metadata_map_lg2phy(cache,
			(rq->map[entry - 1].coll_idx)) + 1 !=
			ocf_metadata_map_lg2phy(cache,
			_entry->coll_idx)) {
			rq->info.seq_req = false;
		}
	}
}

void ocf_engine_traverse(struct ocf_request *rq)
{
	uint32_t i;
	uint64_t core_line;

	struct ocf_cache *cache = rq->cache;
	ocf_core_id_t core_id = rq->core_id;

	OCF_DEBUG_TRACE(rq->cache);

	ocf_rq_clear_info(rq);
	rq->info.seq_req = true;

	for (i = 0, core_line = rq->core_line_first;
			core_line <= rq->core_line_last; core_line++, i++) {

		struct ocf_map_info *entry = &(rq->map[i]);

		ocf_engine_lookup_map_entry(cache, entry, core_id,
				core_line);

		if (entry->status != LOOKUP_HIT) {
			rq->info.seq_req = false;
			/* There is miss then lookup for next map entry */
			OCF_DEBUG_PARAM(cache, "Miss, core line = %llu",
					entry->core_line);
			continue;
		}

		OCF_DEBUG_PARAM(cache, "Hit, cache line %u, core line = %llu",
				entry->coll_idx, entry->core_line);

		/* Update eviction (LRU) */
		ocf_eviction_set_hot_cache_line(cache, entry->coll_idx);

		ocf_engine_update_rq_info(cache, rq, i);
	}

	OCF_DEBUG_PARAM(cache, "Sequential - %s", rq->info.seq_req ?
			"Yes" : "No");
}

int ocf_engine_check(struct ocf_request *rq)
{
	int result = 0;
	uint32_t i;
	uint64_t core_line;

	struct ocf_cache *cache = rq->cache;

	OCF_DEBUG_TRACE(rq->cache);

	ocf_rq_clear_info(rq);
	rq->info.seq_req = true;

	for (i = 0, core_line = rq->core_line_first;
			core_line <= rq->core_line_last; core_line++, i++) {

		struct ocf_map_info *entry = &(rq->map[i]);

		if (entry->status == LOOKUP_MISS) {
			rq->info.seq_req = false;
			continue;
		}

		if (_ocf_engine_check_map_entry(cache, entry, rq->core_id)) {
			/* Mapping is invalid */
			entry->invalid = true;
			rq->info.seq_req = false;

			OCF_DEBUG_PARAM(cache, "Invalid, Cache line %u",
					entry->coll_idx);

			result = -1;
		} else {
			entry->invalid = false;

			OCF_DEBUG_PARAM(cache, "Valid, Cache line %u",
					entry->coll_idx);

			ocf_engine_update_rq_info(cache, rq, i);
		}
	}

	OCF_DEBUG_PARAM(cache, "Sequential - %s", rq->info.seq_req ?
			"Yes" : "No");

	return result;
}

static void ocf_engine_map_cache_line(struct ocf_request *rq,
		uint64_t core_line, unsigned int hash_index,
		ocf_cache_line_t *cache_line)
{
	struct ocf_cache *cache = rq->cache;
	ocf_part_id_t part_id = rq->part_id;
	ocf_cleaning_t clean_policy_type;

	if (cache->device->freelist_part->curr_size == 0) {
		rq->info.eviction_error = 1;
		return;
	}

	*cache_line = cache->device->freelist_part->head;

	/* add_to_collision_list changes .next_col and other fields for entry
	 * so updated last_cache_line_give must be updated before calling it.
	 */

	ocf_metadata_remove_from_free_list(cache, *cache_line);

	ocf_metadata_add_to_partition(cache, part_id, *cache_line);

	/* Add the block to the corresponding collision list */
	ocf_metadata_add_to_collision(cache, rq->core_id, core_line, hash_index,
			*cache_line);

	ocf_eviction_init_cache_line(cache, *cache_line, part_id);

	/* Update LRU:: Move this node to head of lru list. */
	ocf_eviction_set_hot_cache_line(cache, *cache_line);

	/* Update dirty cache-block list */
	clean_policy_type = cache->conf_meta->cleaning_policy_type;

	ENV_BUG_ON(clean_policy_type >= ocf_cleaning_max);

	if (cleaning_policy_ops[clean_policy_type].init_cache_block != NULL)
		cleaning_policy_ops[clean_policy_type].
				init_cache_block(cache, *cache_line);
}

static void ocf_engine_map_hndl_error(struct ocf_cache *cache,
		struct ocf_request *rq)
{
	uint32_t i;
	struct ocf_map_info *entry;

	for (i = 0; i < rq->core_line_count; i++) {
		entry = &(rq->map[i]);

		switch (entry->status) {
		case LOOKUP_HIT:
		case LOOKUP_MISS:
			break;

		case LOOKUP_MAPPED:
			OCF_DEBUG_RQ(rq, "Canceling cache line %u",
					entry->coll_idx);
			set_cache_line_invalid_no_flush(cache, 0,
					ocf_line_end_sector(cache),
					entry->coll_idx);
			break;

		default:
			ENV_BUG();
			break;
		}
	}
}

void ocf_engine_map(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;
	uint32_t i;
	struct ocf_map_info *entry;
	uint64_t core_line;
	int status = LOOKUP_MAPPED;
	ocf_core_id_t core_id = rq->core_id;

	if (ocf_engine_unmapped_count(rq))
		status = space_managment_evict_do(cache, rq,
				ocf_engine_unmapped_count(rq));

	if (rq->info.eviction_error)
		return;

	ocf_rq_clear_info(rq);
	rq->info.seq_req = true;

	OCF_DEBUG_TRACE(rq->cache);

	for (i = 0, core_line = rq->core_line_first;
			core_line <= rq->core_line_last; core_line++, i++) {
		entry = &(rq->map[i]);

		ocf_engine_lookup_map_entry(cache, entry, core_id, core_line);

		if (entry->status != LOOKUP_HIT) {
			ocf_engine_map_cache_line(rq, entry->core_line,
					entry->hash_key, &entry->coll_idx);

			if (rq->info.eviction_error) {
				/*
				 * Eviction error (mapping error), need to
				 * clean, return and do pass through
				 */
				OCF_DEBUG_RQ(rq, "Eviction ERROR when mapping");
				ocf_engine_map_hndl_error(cache, rq);
				break;
			}

			entry->status = status;
		}

		OCF_DEBUG_PARAM(rq->cache,
			"%s, cache line %u, core line = %llu",
			entry->status == LOOKUP_HIT ? "Hit" : "Map",
			entry->coll_idx, entry->core_line);

		ocf_engine_update_rq_info(cache, rq, i);

	}

	OCF_DEBUG_PARAM(rq->cache, "Sequential - %s", rq->info.seq_req ?
			"Yes" : "No");
}

static void _ocf_engine_clean_end(void *private_data, int error)
{
	struct ocf_request *rq = private_data;

	if (error) {
		OCF_DEBUG_RQ(rq, "Cleaning ERROR");
		rq->error |= error;

		/* End request and do not processing */
		ocf_rq_unlock(rq);

		/* Complete request */
		rq->complete(rq, error);

		/* Release OCF request */
		ocf_rq_put(rq);
	} else {
		rq->info.dirty_any = 0;
		rq->info.dirty_all = 0;
		ocf_engine_push_rq_front(rq, true);
	}
}

static int _ocf_engine_clean_getter(struct ocf_cache *cache,
		void *getter_context, uint32_t item, ocf_cache_line_t *line)
{
	struct ocf_cleaner_attribs *attribs = getter_context;
	struct ocf_request *rq = attribs->cmpl_context;

	for (; attribs->getter_item < rq->core_line_count;
			attribs->getter_item++) {

		struct ocf_map_info *entry = &rq->map[attribs->getter_item];

		if (entry->status != LOOKUP_HIT)
			continue;

		if (!metadata_test_dirty(cache, entry->coll_idx))
			continue;

		/* Line to be cleaned found, go to next item and return */
		*line = entry->coll_idx;
		attribs->getter_item++;
		return 0;
	}

	return -1;
}

void ocf_engine_clean(struct ocf_request *rq)
{
	/* Initialize attributes for cleaner */
	struct ocf_cleaner_attribs attribs = {
			.cache_line_lock = false,

			.cmpl_context = rq,
			.cmpl_fn = _ocf_engine_clean_end,

			.getter = _ocf_engine_clean_getter,
			.getter_context = &attribs,
			.getter_item = 0,

			.count = rq->info.dirty_any,
			.io_queue = rq->io_queue
	};

	/* Start cleaning */
	ocf_cleaner_fire(rq->cache, &attribs);
}

void ocf_engine_update_block_stats(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;
	ocf_core_id_t core_id = rq->core_id;
	ocf_part_id_t part_id = rq->part_id;
	struct ocf_counters_block *blocks;

	blocks = &cache->core_obj[core_id].counters->
			part_counters[part_id].blocks;

	if (rq->rw == OCF_READ)
		env_atomic64_add(rq->byte_length, &blocks->read_bytes);
	else if (rq->rw == OCF_WRITE)
		env_atomic64_add(rq->byte_length, &blocks->write_bytes);
	else
		ENV_BUG();
}

void ocf_engine_update_request_stats(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;
	ocf_core_id_t core_id = rq->core_id;
	ocf_part_id_t part_id = rq->part_id;
	struct ocf_counters_req *reqs;

	switch (rq->rw) {
	case OCF_READ:
		reqs = &cache->core_obj[core_id].counters->
				part_counters[part_id].read_reqs;
		break;
	case OCF_WRITE:
		reqs = &cache->core_obj[core_id].counters->
				part_counters[part_id].write_reqs;
		break;
	default:
		ENV_BUG();
	}

	env_atomic64_inc(&reqs->total);

	if (rq->info.hit_no == 0)
		env_atomic64_inc(&reqs->full_miss);
	else if (rq->info.hit_no < rq->core_line_count)
		env_atomic64_inc(&reqs->partial_miss);
}

void ocf_engine_push_rq_back(struct ocf_request *rq, bool allow_sync)
{
	struct ocf_cache *cache = rq->cache;
	struct ocf_queue *q = NULL;
	unsigned long lock_flags;

	INIT_LIST_HEAD(&rq->list);

	ENV_BUG_ON(rq->io_queue >= cache->io_queues_no);
	q = &cache->io_queues[rq->io_queue];

	env_spinlock_lock_irqsave(&q->io_list_lock, lock_flags);

	list_add_tail(&rq->list, &q->io_list);
	env_atomic_inc(&q->io_no);

	env_spinlock_unlock_irqrestore(&q->io_list_lock, lock_flags);

	if (!rq->info.internal)
		env_atomic_set(&cache->last_access_ms,
				env_ticks_to_msecs(env_get_tick_count()));

	ctx_queue_kick(cache->owner, q, allow_sync);
}

void ocf_engine_push_rq_front(struct ocf_request *rq, bool allow_sync)
{
	struct ocf_cache *cache = rq->cache;
	struct ocf_queue *q = NULL;
	unsigned long lock_flags;

	INIT_LIST_HEAD(&rq->list);

	ENV_BUG_ON(rq->io_queue >= cache->io_queues_no);
	q = &cache->io_queues[rq->io_queue];

	env_spinlock_lock_irqsave(&q->io_list_lock, lock_flags);

	list_add(&rq->list, &q->io_list);
	env_atomic_inc(&q->io_no);

	env_spinlock_unlock_irqrestore(&q->io_list_lock, lock_flags);

	if (!rq->info.internal)
		env_atomic_set(&cache->last_access_ms,
				env_ticks_to_msecs(env_get_tick_count()));

	ctx_queue_kick(cache->owner, q, allow_sync);
}

void ocf_engine_push_rq_front_if(struct ocf_request *rq,
		const struct ocf_io_if *io_if,
		bool allow_sync)
{
	rq->error = 0; /* Please explain why!!! */
	rq->io_if = io_if;
	ocf_engine_push_rq_front(rq, allow_sync);
}

void inc_fallback_pt_error_counter(ocf_cache_t cache)
{
	ENV_BUG_ON(env_atomic_read(&cache->fallback_pt_error_counter) < 0);

	if (cache->fallback_pt_error_threshold == OCF_CACHE_FALLBACK_PT_INACTIVE)
		return;

	if (env_atomic_inc_return(&cache->fallback_pt_error_counter) ==
			cache->fallback_pt_error_threshold) {
		ocf_cache_log(cache, log_info, "Error threshold reached. "
				"Fallback Pass Through activated\n");
	}
}

static int _ocf_engine_refresh(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;
	int result;

	OCF_METADATA_LOCK_RD();
	/* Check under metadata RD lock */

	result = ocf_engine_check(rq);

	OCF_METADATA_UNLOCK_RD();

	if (result == 0) {

		/* Refresh successful, can process with original IO interface */
		rq->io_if = rq->priv;

		rq->resume = NULL;
		rq->priv = NULL;

		if (rq->rw == OCF_READ)
			rq->io_if->read(rq);
		else if (rq->rw == OCF_WRITE)
			rq->io_if->write(rq);
		else
			ENV_BUG();
	} else {
		ENV_WARN(true, "Inconsistent request");
		rq->error = -EINVAL;

		/* Complete request */
		rq->complete(rq, rq->error);

		/* Release WRITE lock of request */
		ocf_rq_unlock(rq);

		/* Release OCF request */
		ocf_rq_put(rq);
	}

	return 0;
}

static const struct ocf_io_if _io_if_refresh = {
		.read = _ocf_engine_refresh,
		.write = _ocf_engine_refresh,
};

void ocf_engine_on_resume(struct ocf_request *rq)
{
	ENV_BUG_ON(rq->priv);
	ENV_BUG_ON(ocf_engine_on_resume != rq->resume);
	OCF_CHECK_NULL(rq->io_if);

	/* Exchange IO interface */
	rq->priv = (void *)rq->io_if;

	OCF_DEBUG_RQ(rq, "On resume");

	ocf_engine_push_rq_front_if(rq, &_io_if_refresh, false);
}
