/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024-2025 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_CACHE_PRIV_H__
#define __OCF_CACHE_PRIV_H__

#include "ocf/ocf.h"
#include "ocf_env.h"
#include "ocf_volume_priv.h"
#include "ocf_core_priv.h"
#include "ocf_part.h"
#include "metadata/metadata_structs.h"
#include "utils/utils_list.h"
#include "utils/utils_pipeline.h"
#include "utils/utils_async_lock.h"
#include "ocf_stats_priv.h"
#include "cleaning/cleaning.h"
#include "ocf_logger_priv.h"
#include "ocf_queue_priv.h"
#include "promotion/promotion.h"

#define DIRTY_FLUSHED 1
#define DIRTY_NOT_FLUSHED 0

/* Cache device */
struct ocf_cache_device {
	struct ocf_volume front_volume;
	struct ocf_volume volume;

	/* Hash Table contains contains pointer to the entry in
	 * Collision Table so it actually contains collision Table
	 * indexes.
	 * Invalid entry is collision_table_entries.
	 */
	unsigned int hash_table_entries;
	unsigned int collision_table_entries;

	int metadata_error;
		/*!< This field indicates that an error during metadata IO
		 * occurred
	 */

	uint64_t metadata_offset;

	struct {
		struct ocf_alock *cache_line;
	} concurrency;

	struct ocf_superblock_runtime *runtime_meta;
};

struct ocf_cache {
	char name[OCF_CACHE_NAME_SIZE];

	ocf_ctx_t owner;

	struct list_head list;

	/* unset running to not serve any more I/O requests */
	unsigned long cache_state;

	struct ocf_superblock_config *conf_meta;

	struct ocf_cache_device *device;

	struct ocf_lst user_part_list;
	struct ocf_user_part user_parts[OCF_USER_IO_CLASS_MAX + 1];

	struct ocf_part free;

	uint32_t fallback_pt_error_threshold;
	ocf_queue_t mngt_queue;

	struct ocf_metadata metadata;

	struct {
		/* cache get/put counter */
		struct env_refcnt cache;
		/* # of requests potentially dirtying cachelines */
		struct env_refcnt dirty;
		/* # of requests accessing attached metadata, excluding
		 * management reqs */
		struct env_refcnt metadata;
		/* # of requests in d2c mode */
		struct env_refcnt d2c;
		/* # of unsettled cache lock operations (lock not acquired,
		 * waiter not added yet) */
		struct env_refcnt lock;
	} refcnt;

	struct {
		env_allocator *allocator;
		struct ocf_alock *concurrency;
	} standby;

	struct ocf_core core[OCF_CORE_MAX];

	ocf_pipeline_t stop_pipeline;

	env_atomic fallback_pt_error_counter;

	env_atomic pending_read_misses_list_blocked;
	env_atomic pending_read_misses_list_count;

	env_atomic flush_in_progress;
	env_mutex flush_mutex;

	env_atomic attach_pt;

	struct ocf_cleaner cleaner;

	struct list_head io_queues;
	env_spinlock io_queues_lock;

	ocf_promotion_policy_t promotion_policy;

	struct {
		uint32_t max_queue_size;
		uint32_t queue_unblock_size;
	} backfill;

	void *priv;

	/*
	 * Most of the time this variable is set to 0, unless user requested
	 * interruption of flushing process.
	 */
	int flushing_interrupted;

	uint16_t ocf_core_inactive_count;

	bool pt_unaligned_io;

	bool use_submit_io_fast;

	struct {
		struct ocf_async_lock lock;
	} __attribute__((aligned(64)));
	// This should be on it's own cacheline ideally
	env_atomic last_access_ms;
};

static inline ocf_core_t ocf_cache_get_core(ocf_cache_t cache,
		ocf_core_id_t core_id)
{
	if (core_id >= OCF_CORE_MAX)
		return NULL;

	return &cache->core[core_id];
}

#define for_each_core_all(_cache, _core, _id) \
	for (_id = 0; _core = &_cache->core[_id], _id < OCF_CORE_MAX; _id++)

#define for_each_core(_cache, _core, _id) \
	for_each_core_all(_cache, _core, _id) \
		if (_core->added)

#define for_each_core_metadata(_cache, _core, _id) \
	for_each_core_all(_cache, _core, _id) \
		if (_core->conf_meta->valid)

#define ocf_cache_log_prefix(cache, lvl, prefix, fmt, ...) \
	ocf_log_prefix(ocf_cache_get_ctx(cache), lvl, "%s" prefix, \
			fmt, ocf_cache_get_name(cache), ##__VA_ARGS__)

#define ocf_cache_log(cache, lvl, fmt, ...) \
	ocf_cache_log_prefix(cache, lvl, ": ", fmt, ##__VA_ARGS__)

#define ocf_cache_log_rl(cache) \
	ocf_log_rl(ocf_cache_get_ctx(cache))

static inline uint64_t ocf_get_cache_occupancy(ocf_cache_t cache)
{
	uint64_t result = 0;
	ocf_core_t core;
	ocf_core_id_t core_id;

	for_each_core(cache, core, core_id)
		result += env_atomic_read(&core->runtime_meta->cached_clines);

	return result;
}

uint32_t ocf_cache_get_queue_count(ocf_cache_t cache);

int ocf_cache_set_name(ocf_cache_t cache, const char *src, size_t src_size);

int ocf_cache_volume_type_init(ocf_ctx_t ctx);

bool ocf_cache_mode_is_valid(ocf_cache_mode_t mode);

#endif /* __OCF_CACHE_PRIV_H__ */
