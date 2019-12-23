/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_CACHE_PRIV_H__
#define __OCF_CACHE_PRIV_H__

#include "ocf/ocf.h"
#include "ocf_env.h"
#include "ocf_volume_priv.h"
#include "ocf_core_priv.h"
#include "metadata/metadata_structs.h"
#include "metadata/metadata_partition_structs.h"
#include "metadata/metadata_updater_priv.h"
#include "utils/utils_list.h"
#include "utils/utils_pipeline.h"
#include "utils/utils_refcnt.h"
#include "utils/utils_async_lock.h"
#include "ocf_stats_priv.h"
#include "cleaning/cleaning.h"
#include "ocf_logger_priv.h"
#include "ocf/ocf_trace.h"
#include "promotion/promotion.h"
#include "ocf_freelist.h"

#define DIRTY_FLUSHED 1
#define DIRTY_NOT_FLUSHED 0

/**
 * @brief Structure used for aggregating trace-related ocf_cache fields
 */
struct ocf_trace {
	/* Placeholder for push_event callback */
	ocf_trace_callback_t trace_callback;

	/* Telemetry context */
	void *trace_ctx;

	env_atomic64 trace_seq_ref;
};

/**
 * @brief Initialization mode of cache instance
 */
enum ocf_mngt_cache_init_mode {
	/**
	 * @brief Set up an SSD as new caching device
	 */
	ocf_init_mode_init,

	/**
	 * @brief Set up an SSD as new caching device without saving cache
	 * metadata on SSD.
	 *
	 * When using this initialization mode, after shutdown, loading cache
	 * is not possible
	 */
	ocf_init_mode_metadata_volatile,

	/**
	 * @brief Load pre-existing SSD cache state and set all parameters
	 *		to previous configurations
	 */
	ocf_init_mode_load,
};

/* Cache device */
struct ocf_cache_device {
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
		struct ocf_cache_line_concurrency *cache_line;
	} concurrency;

	enum ocf_mngt_cache_init_mode init_mode;

	struct ocf_superblock_runtime *runtime_meta;
};

struct ocf_cache {
	ocf_ctx_t owner;

	struct list_head list;

	/* unset running to not serve any more I/O requests */
	unsigned long cache_state;

	struct ocf_superblock_config *conf_meta;

	struct ocf_cache_device *device;

	struct ocf_lst lst_part;
	struct ocf_user_part user_parts[OCF_IO_CLASS_MAX + 1];

	struct ocf_metadata metadata;

	ocf_freelist_t freelist;

	ocf_eviction_t eviction_policy_init;

	struct {
		/* cache get/put counter */
		struct ocf_refcnt cache;
		/* # of requests potentially dirtying cachelines */
		struct ocf_refcnt dirty;
		/* # of requests accessing attached metadata, excluding
		 * management reqs */
		struct ocf_refcnt metadata;
		/* # of forced cleaning requests (eviction path) */
		struct ocf_refcnt cleaning[OCF_IO_CLASS_MAX];
	} refcnt;

	uint32_t fallback_pt_error_threshold;
	env_atomic fallback_pt_error_counter;

	env_atomic pending_read_misses_list_blocked;
	env_atomic pending_read_misses_list_count;

	env_atomic last_access_ms;

	env_atomic pending_eviction_clines;

	struct list_head io_queues;
	ocf_queue_t mngt_queue;

	uint16_t ocf_core_inactive_count;
	struct ocf_core core[OCF_CORE_MAX];

	env_atomic flush_in_progress;

	struct ocf_cleaner cleaner;
	struct ocf_metadata_updater metadata_updater;
	ocf_promotion_policy_t promotion_policy;

	struct ocf_async_lock lock;

	/*
	 * Most of the time this variable is set to 0, unless user requested
	 * interruption of flushing process.
	 */
	int flushing_interrupted;
	env_mutex flush_mutex;

	struct {
		uint32_t max_queue_size;
		uint32_t queue_unblock_size;
	} backfill;

	bool pt_unaligned_io;

	bool use_submit_io_fast;

	struct ocf_trace trace;

	ocf_pipeline_t stop_pipeline;

	void *priv;
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

int ocf_cache_set_name(ocf_cache_t cache, const char *src, size_t src_size);

#endif /* __OCF_CACHE_PRIV_H__ */
