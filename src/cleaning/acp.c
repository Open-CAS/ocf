/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "cleaning.h"
#include "../metadata/metadata.h"
#include "../utils/utils_cleaner.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_req.h"
#include "../cleaning/acp.h"
#include "../engine/engine_common.h"
#include "../concurrency/ocf_cache_concurrency.h"
#include "cleaning_priv.h"

#define OCF_ACP_DEBUG 0

#if 1 == OCF_ACP_DEBUG

#define OCF_DEBUG_PREFIX "[Clean] %s():%d "

#define OCF_DEBUG_LOG(cache, format, ...) \
	ocf_cache_log_prefix(cache, log_info, OCF_DEBUG_PREFIX, \
			format"\n", __func__, __LINE__, ##__VA_ARGS__)

#define OCF_DEBUG_TRACE(cache) OCF_DEBUG_LOG(cache, "")

#define OCF_DEBUG_MSG(cache, msg) OCF_DEBUG_LOG(cache, "- %s", msg)

#define OCF_DEBUG_PARAM(cache, format, ...) OCF_DEBUG_LOG(cache, "- "format, \
			##__VA_ARGS__)

#define ACP_DEBUG_INIT(acp) acp->checksum = 0
#define ACP_DEBUG_BEGIN(acp, cache_line) acp->checksum ^= cache_line
#define ACP_DEBUG_END(acp, cache_line) acp->checksum ^= cache_line
#define ACP_DEBUG_CHECK(acp) ENV_BUG_ON(acp->checksum)
#else
#define OCF_DEBUG_PREFIX
#define OCF_DEBUG_LOG(cache, format, ...)
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_MSG(cache, msg)
#define OCF_DEBUG_PARAM(cache, format, ...)
#define ACP_DEBUG_INIT(acp)
#define ACP_DEBUG_BEGIN(acp, cache_line)
#define ACP_DEBUG_END(acp, cache_line)
#define ACP_DEBUG_CHECK(acp)
#endif

#define ACP_CHUNK_SIZE (100 * MiB)

/* minimal time to chunk cleaning after error */
#define ACP_CHUNK_CLEANING_BACKOFF_TIME 5

/* time to sleep when nothing to clean in ms */
#define ACP_BACKOFF_TIME_MS 1000

#define ACP_MAX_BUCKETS 11

/* Upper thresholds for buckets in percent dirty pages. First bucket should have
 * threshold=0 - it isn't cleaned and we don't want dirty chunks staying dirty
 * forever. Last bucket also should stay at 100 for obvious reasons */
static const uint16_t ACP_BUCKET_DEFAULTS[ACP_MAX_BUCKETS] = { 0, 10, 20, 30, 40,
		50, 60, 70, 80, 90, 100 };

struct acp_flush_context {
	/* number of cache lines in flush */
	uint64_t size;
	/* chunk_for error handling */
	struct acp_chunk_info *chunk;
	/* cache lines to flush */
	struct flush_data data[OCF_ACP_MAX_FLUSH_MAX_BUFFERS];
	/* flush error code */
	int error;
};

struct acp_state {
	/* currently cleaned chunk */
	struct acp_chunk_info *chunk;

	/* cache line iterator within current chunk */
	unsigned iter;

	/* true if there are cache lines to process
	 * current chunk */
	bool in_progress;
};

struct acp_chunk_info {
	struct list_head list;
	uint64_t chunk_id;
	uint64_t next_cleaning_timestamp;
	ocf_core_id_t core_id;
	uint16_t num_dirty;
	uint8_t bucket_id;
};

struct acp_bucket {
	struct list_head chunk_list;
	uint16_t threshold; /* threshold in clines */
};

struct acp_context {
	env_rwsem chunks_lock;

	/* number of chunks per core */
	uint64_t num_chunks[OCF_CORE_MAX];

	/* per core array of all chunks */
	struct acp_chunk_info *chunk_info[OCF_CORE_MAX];

	struct acp_bucket bucket_info[ACP_MAX_BUCKETS];

	/* total number of chunks in cache */
	uint64_t chunks_total;

	/* structure to keep track of I/O in progress */
	struct acp_flush_context flush;

	/* cleaning state persistent over subsequent calls to
	 perform_cleaning */
	struct acp_state state;

#if 1 == OCF_ACP_DEBUG
	/* debug only */
	uint64_t checksum;
#endif
};

struct acp_core_line_info
{
	ocf_cache_line_t cache_line;
	ocf_core_id_t core_id;
	uint64_t core_line;
};

#define ACP_LOCK_CHUNKS_RD() env_rwsem_down_read(&acp->chunks_lock)

#define ACP_UNLOCK_CHUNKS_RD() env_rwsem_up_read(&acp->chunks_lock)

#define ACP_LOCK_CHUNKS_WR() env_rwsem_down_write(&acp->chunks_lock)

#define ACP_UNLOCK_CHUNKS_WR() env_rwsem_up_write(&acp->chunks_lock)

static struct acp_context *_acp_get_ctx_from_cache(struct ocf_cache *cache)
{
	return cache->cleaning_policy_context;
}

static struct acp_cleaning_policy_meta* _acp_meta_get(
		struct ocf_cache *cache, uint32_t cache_line,
		struct cleaning_policy_meta *policy_meta)
{
	ocf_metadata_get_cleaning_policy(cache, cache_line, policy_meta);
	return &policy_meta->meta.acp;
}

static void _acp_meta_set(struct ocf_cache *cache, uint32_t cache_line,
		struct cleaning_policy_meta *policy_meta)
{
	ocf_metadata_set_cleaning_policy(cache, cache_line, policy_meta);
}

static struct acp_core_line_info _acp_core_line_info(struct ocf_cache *cache,
		ocf_cache_line_t cache_line)
{
	struct acp_core_line_info acp_core_line_info = {.cache_line = cache_line, };
	ocf_metadata_get_core_info(cache, cache_line, &acp_core_line_info.core_id,
		&acp_core_line_info.core_line);
	return acp_core_line_info;
}

static struct acp_chunk_info *_acp_get_chunk(struct ocf_cache *cache,
		uint32_t cache_line)
{
	struct acp_context *acp = _acp_get_ctx_from_cache(cache);
	struct acp_core_line_info core_line =
			_acp_core_line_info(cache, cache_line);
	uint64_t chunk_id;

	chunk_id = core_line.core_line * ocf_line_size(cache) / ACP_CHUNK_SIZE;

	return &acp->chunk_info[core_line.core_id][chunk_id];
}

#define for_each_core(cache, iter) \
	for (iter = 0; iter < OCF_CORE_MAX; iter++) \
		if (cache->core_conf_meta[iter].added)

static void _acp_remove_cores(struct ocf_cache *cache)
{
	int i;

	for_each_core(cache, i)
		cleaning_policy_acp_remove_core(cache, i);
}

static int _acp_load_cores(struct ocf_cache *cache)
{
	int i;
	int err = 0;

	for_each_core(cache, i) {
		OCF_DEBUG_PARAM(cache, "loading core %i\n", i);
		err = cleaning_policy_acp_add_core(cache, i);
		if (err)
			break;
	}

	if (err)
		_acp_remove_cores(cache);

	return err;
}

void cleaning_policy_acp_init_cache_block(struct ocf_cache *cache,
		uint32_t cache_line)
{
	struct cleaning_policy_meta policy_meta;
	struct acp_cleaning_policy_meta *acp_meta;

	/* TODO: acp meta is going to be removed soon */
	acp_meta = _acp_meta_get(cache, cache_line, &policy_meta);
	acp_meta->dirty = 0;
	_acp_meta_set(cache, cache_line, &policy_meta);
}

void cleaning_policy_acp_deinitialize(struct ocf_cache *cache)
{
	_acp_remove_cores(cache);

	env_vfree(cache->cleaning_policy_context);
	cache->cleaning_policy_context = NULL;
}

static void _acp_rebuild(struct ocf_cache *cache)
{
	ocf_cache_line_t cline;
	ocf_core_id_t cline_core_id;
	uint32_t step = 0;

	for (cline = 0; cline < cache->device->collision_table_entries; cline++) {
		ocf_metadata_get_core_and_part_id(cache, cline, &cline_core_id,
				NULL);

		OCF_COND_RESCHED_DEFAULT(step);

		if (cline_core_id == OCF_CORE_MAX)
			continue;

		cleaning_policy_acp_init_cache_block(cache, cline);

		if (!metadata_test_dirty(cache, cline))
			continue;

		cleaning_policy_acp_set_hot_cache_line(cache, cline);
	}

	ocf_cache_log(cache, log_info, "Finished rebuilding ACP metadata\n");
}

void cleaning_policy_acp_setup(struct ocf_cache *cache)
{
	struct acp_cleaning_policy_config *config;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_acp].data;

	config->thread_wakeup_time = OCF_ACP_DEFAULT_WAKE_UP;
	config->flush_max_buffers = OCF_ACP_DEFAULT_FLUSH_MAX_BUFFERS;
}

int cleaning_policy_acp_initialize(struct ocf_cache *cache,
		int init_metadata)
{
	struct acp_context *acp;
	int err, i;

	/* bug if max chunk number would overflow dirty_no array type */
#if defined (BUILD_BUG_ON)
	BUILD_BUG_ON(ACP_CHUNK_SIZE / ocf_cache_line_size_min >=
			1U << (sizeof(acp->chunk_info[0][0].num_dirty) * 8));
#else
	ENV_BUG_ON(ACP_CHUNK_SIZE / ocf_cache_line_size_min >=
			1U << (sizeof(acp->chunk_info[0][0].num_dirty) * 8));
#endif

	ENV_BUG_ON(cache->cleaning_policy_context);

	cache->cleaning_policy_context = env_vzalloc(sizeof(struct acp_context));
	if (!cache->cleaning_policy_context) {
		ocf_cache_log(cache, log_err, "acp context allocation error\n");
		return -OCF_ERR_NO_MEM;
	}
	acp = cache->cleaning_policy_context;

	env_rwsem_init(&acp->chunks_lock);

	for (i = 0; i < ACP_MAX_BUCKETS; i++) {
		INIT_LIST_HEAD(&acp->bucket_info[i].chunk_list);
		acp->bucket_info[i].threshold =
			((ACP_CHUNK_SIZE/ocf_line_size(cache)) *
			 ACP_BUCKET_DEFAULTS[i]) / 100;
	}

	if (cache->conf_meta->core_count > 0) {
		err = _acp_load_cores(cache);
		if (err) {
			cleaning_policy_acp_deinitialize(cache);
			return err;
		}
	}

	_acp_rebuild(cache);

	return 0;
}

int cleaning_policy_acp_set_cleaning_param(ocf_cache_t cache,
		uint32_t param_id, uint32_t param_value)
{
	struct acp_cleaning_policy_config *config;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_acp].data;

	switch (param_id) {
	case ocf_acp_wake_up_time:
		OCF_CLEANING_CHECK_PARAM(cache, param_value,
				OCF_ACP_MIN_WAKE_UP,
				OCF_ACP_MAX_WAKE_UP,
				"thread_wakeup_time");
		config->thread_wakeup_time = param_value;
		ocf_cache_log(cache, log_info, "Write-back flush thread "
			"wake-up time: %d\n", config->thread_wakeup_time);
		break;
	case ocf_acp_flush_max_buffers:
		OCF_CLEANING_CHECK_PARAM(cache, param_value,
				OCF_ACP_MIN_FLUSH_MAX_BUFFERS,
				OCF_ACP_MAX_FLUSH_MAX_BUFFERS,
				"flush_max_buffers");
		config->flush_max_buffers = param_value;
		ocf_cache_log(cache, log_info, "Write-back flush thread max "
			"buffers flushed per iteration: %d\n",
			config->flush_max_buffers);
		break;
	default:
		return -OCF_ERR_INVAL;
	}

	return 0;
}

int cleaning_policy_acp_get_cleaning_param(ocf_cache_t cache,
		uint32_t param_id, uint32_t *param_value)
{
	struct acp_cleaning_policy_config *config;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_acp].data;

	switch (param_id) {
	case ocf_acp_flush_max_buffers:
		*param_value = config->flush_max_buffers;
		break;
	case ocf_acp_wake_up_time:
		*param_value = config->thread_wakeup_time;
		break;
	default:
		return -OCF_ERR_INVAL;
	}

	return 0;
}


/* attempt to lock cache line if it's dirty */
static ocf_cache_line_t _acp_trylock_dirty(struct ocf_cache *cache,
		uint32_t core_id, uint64_t core_line)
{
	struct ocf_map_info info;
	bool locked = false;

	OCF_METADATA_LOCK_RD();

	ocf_engine_lookup_map_entry(cache, &info, core_id,
			core_line);

	if (info.status == LOOKUP_HIT &&
			metadata_test_dirty(cache, info.coll_idx) &&
			ocf_cache_line_try_lock_rd(cache, info.coll_idx)) {
		locked = true;
	}

	OCF_METADATA_UNLOCK_RD();

	return locked ? info.coll_idx : cache->device->collision_table_entries;
}

static void _acp_handle_flush_error(struct ocf_cache *cache,
		struct acp_context *acp)
{
	struct acp_flush_context *flush = &acp->flush;

	flush->chunk->next_cleaning_timestamp = env_get_tick_count() +
			env_secs_to_ticks(ACP_CHUNK_CLEANING_BACKOFF_TIME);

	if (ocf_cache_log_rl(cache)) {
		ocf_core_log(&cache->core[flush->chunk->core_id],
				log_err, "Cleaning error (%d) in range"
				" <%llu; %llu) backing off for %u seconds\n",
				flush->error,
				flush->chunk->chunk_id * ACP_CHUNK_SIZE,
				(flush->chunk->chunk_id * ACP_CHUNK_SIZE) +
						ACP_CHUNK_SIZE,
				ACP_CHUNK_CLEANING_BACKOFF_TIME);
	}
}

/* called after flush request completed */
static void _acp_flush_end(
		struct ocf_cache *cache,
		struct acp_context *acp)
{
	struct acp_flush_context *flush = &acp->flush;
	int i;

	for (i = 0; i < flush->size; i++) {
		ocf_cache_line_unlock_rd(cache, flush->data[i].cache_line);
		ACP_DEBUG_END(acp, flush->data[i].cache_line);
	}

	if (flush->error)
		_acp_handle_flush_error(cache, acp);
}

/* flush data  */
static void _acp_flush(struct ocf_cache *cache, struct acp_context *acp,
		uint32_t io_queue, struct acp_flush_context *flush)
{
	struct ocf_cleaner_attribs attribs = {
		.cache_line_lock = false,
		.metadata_locked = false,
		.do_sort = false,
		.io_queue = io_queue,
	};

	flush->error = ocf_cleaner_do_flush_data(cache, flush->data,
			flush->size, &attribs);

	_acp_flush_end(cache, acp);
}

static inline bool _acp_can_clean_chunk(struct ocf_cache *cache,
		struct acp_chunk_info *chunk)
{
	/* Check if core device is opened and if timeout after cleaning error
	 * expired or wasn't set in the first place */
	return (cache->core[chunk->core_id].opened &&
			(chunk->next_cleaning_timestamp > env_get_tick_count() ||
					!chunk->next_cleaning_timestamp));
}

static struct acp_chunk_info *_acp_get_cleaning_candidate(
		struct ocf_cache *cache)
{
	int i;
	struct acp_chunk_info *cur;
	struct acp_context *acp = cache->cleaning_policy_context;

	ACP_LOCK_CHUNKS_RD();

	/* go through all buckets in descending order, excluding bucket 0 which
	 * is supposed to contain all clean chunks */
	for (i = ACP_MAX_BUCKETS - 1; i > 0; i--) {
		list_for_each_entry(cur, &acp->bucket_info[i].chunk_list, list) {
			if (_acp_can_clean_chunk(cache, cur)) {
				ACP_UNLOCK_CHUNKS_RD();
				return cur;
			}
		}
	}

	ACP_UNLOCK_CHUNKS_RD();
	return NULL;
}

#define CHUNK_FINISHED -1

/* clean at most 'flush_max_buffers' cache lines from given chunk, starting
 * at given cache line */
static int _acp_clean(struct ocf_cache *cache, uint32_t io_queue,
		struct acp_chunk_info *chunk, unsigned start,
		uint32_t flush_max_buffers)
{
	struct acp_context *acp = _acp_get_ctx_from_cache(cache);
	size_t lines_per_chunk = ACP_CHUNK_SIZE /
			ocf_line_size(cache);
	uint64_t first_core_line = chunk->chunk_id * lines_per_chunk;
	unsigned i;

	OCF_DEBUG_PARAM(cache, "lines per chunk %llu chunk %llu "
			"first_core_line %llu\n",
			(uint64_t)lines_per_chunk,
			chunk->chunk_id,
			first_core_line);

	ACP_DEBUG_INIT(acp);

	acp->flush.size = 0;
	acp->flush.chunk = chunk;
	for (i = start; i < lines_per_chunk && acp->flush.size < flush_max_buffers ; i++) {
		uint64_t core_line = first_core_line + i;
		ocf_cache_line_t cache_line;

		cache_line = _acp_trylock_dirty(cache, chunk->core_id, core_line);
		if (cache_line == cache->device->collision_table_entries)
			continue;

		acp->flush.data[acp->flush.size].core_id =  chunk->core_id;
		acp->flush.data[acp->flush.size].core_line =  core_line;
		acp->flush.data[acp->flush.size].cache_line = cache_line;
		acp->flush.size++;
		ACP_DEBUG_BEGIN(acp, cache_line);
	}

	if (acp->flush.size > 0) {
		_acp_flush(cache, acp, io_queue, &acp->flush);
	}

	ACP_DEBUG_CHECK(acp);

	return (i == lines_per_chunk) ? CHUNK_FINISHED : i;
}

#define NOTHING_TO_CLEAN 0
#define MORE_TO_CLEAN 1

/* Clean at most 'flush_max_buffers' cache lines from current or newly
 * selected chunk */
static int _acp_clean_iteration(struct ocf_cache *cache, uint32_t io_queue,
		uint32_t flush_max_buffers)
{
	struct acp_context *acp = _acp_get_ctx_from_cache(cache);
	struct acp_state *state = &acp->state;

	if (!state->in_progress) {
		/* get next chunk to clean */
		state->chunk = _acp_get_cleaning_candidate(cache);

		if (!state->chunk) {
			/* nothing co clean */
			return  NOTHING_TO_CLEAN;
		}

		/* new cleaning cycle - reset state */
		state->iter = 0;
		state->in_progress = true;
	}

	state->iter = _acp_clean(cache, io_queue, state->chunk, state->iter,
					flush_max_buffers);

	if (state->iter == CHUNK_FINISHED) {
		/* reached end of chunk - reset state */
		state->in_progress = false;
	}


	return MORE_TO_CLEAN;
}

int cleaning_policy_acp_perform_cleaning(struct ocf_cache *cache,
		uint32_t io_queue)
{
	struct acp_cleaning_policy_config *config;
	int ret;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_acp].data;

	if (NOTHING_TO_CLEAN == _acp_clean_iteration(cache, io_queue,
					config->flush_max_buffers)) {
		ret = ACP_BACKOFF_TIME_MS;
	} else {
		ret = config->thread_wakeup_time;
	}

	return ret;
}

static void _acp_update_bucket(struct acp_context *acp,
		struct acp_chunk_info *chunk)
{
	struct acp_bucket *bucket = &acp->bucket_info[chunk->bucket_id];

	if (chunk->num_dirty > bucket->threshold) {
		ENV_BUG_ON(chunk->bucket_id == ACP_MAX_BUCKETS - 1);

		chunk->bucket_id++;
		/* buckets are stored in array, move up one bucket.
		 * No overflow here. ENV_BUG_ON made sure of no incrementation on
		 * last bucket */
		bucket++;

		list_move_tail(&chunk->list, &bucket->chunk_list);
	} else if (chunk->bucket_id &&
			chunk->num_dirty <= (bucket - 1)->threshold) {
		chunk->bucket_id--;
		/* move down one bucket, we made sure we won't underflow */
		bucket--;

		list_move(&chunk->list, &bucket->chunk_list);
	}
}

void cleaning_policy_acp_set_hot_cache_line(struct ocf_cache *cache,
		uint32_t cache_line)
{
	struct acp_context *acp = _acp_get_ctx_from_cache(cache);
	struct cleaning_policy_meta policy_meta;
	struct acp_cleaning_policy_meta *acp_meta;
	struct acp_chunk_info *chunk;

	ACP_LOCK_CHUNKS_WR();

	acp_meta = _acp_meta_get(cache, cache_line, &policy_meta);
	chunk = _acp_get_chunk(cache, cache_line);

	if (!acp_meta->dirty) {
		acp_meta->dirty = 1;
		_acp_meta_set(cache, cache_line, &policy_meta);
		chunk->num_dirty++;
	}

	_acp_update_bucket(acp, chunk);

	ACP_UNLOCK_CHUNKS_WR();
}

void cleaning_policy_acp_purge_block(struct ocf_cache *cache,
		uint32_t cache_line)
{
	struct acp_context *acp = _acp_get_ctx_from_cache(cache);
	struct cleaning_policy_meta policy_meta;
	struct acp_cleaning_policy_meta *acp_meta;
	struct acp_chunk_info *chunk;

	acp_meta = _acp_meta_get(cache, cache_line, &policy_meta);
	chunk = _acp_get_chunk(cache, cache_line);

	if (acp_meta->dirty) {
		acp_meta->dirty = 0;
		_acp_meta_set(cache, cache_line, &policy_meta);
		chunk->num_dirty--;
	}

	_acp_update_bucket(acp, chunk);
}

int cleaning_policy_acp_purge_range(struct ocf_cache *cache,
		int core_id, uint64_t start_byte, uint64_t end_byte)
{
	return ocf_metadata_actor(cache, PARTITION_INVALID,
			core_id, start_byte, end_byte,
			cleaning_policy_acp_purge_block);
}

void cleaning_policy_acp_remove_core(ocf_cache_t cache,
		ocf_core_id_t core_id)
{
	struct acp_context *acp  = _acp_get_ctx_from_cache(cache);
	uint64_t i;

	ENV_BUG_ON(acp->chunks_total < acp->num_chunks[core_id]);

	if (acp->state.in_progress && acp->state.chunk->core_id == core_id) {
		acp->state.in_progress = false;
		acp->state.iter = 0;
		acp->state.chunk = NULL;
	}

	ACP_LOCK_CHUNKS_WR();

	for (i = 0; i < acp->num_chunks[core_id]; i++)
		list_del(&acp->chunk_info[core_id][i].list);

	acp->chunks_total -= acp->num_chunks[core_id];
	acp->num_chunks[core_id] = 0;

	env_vfree(acp->chunk_info[core_id]);
	acp->chunk_info[core_id] = NULL;

	ACP_UNLOCK_CHUNKS_WR();
}

int cleaning_policy_acp_add_core(ocf_cache_t cache,
		ocf_core_id_t core_id)
{
	uint64_t core_size = cache->core_conf_meta[core_id].length;
	uint64_t num_chunks = DIV_ROUND_UP(core_size, ACP_CHUNK_SIZE);
	struct acp_context *acp = _acp_get_ctx_from_cache(cache);
	int i;

	OCF_DEBUG_PARAM(cache, "%s core_id %llu num_chunks %llu\n",
			__func__, (uint64_t)core_id, (uint64_t) num_chunks);

	ACP_LOCK_CHUNKS_WR();

	ENV_BUG_ON(acp->chunk_info[core_id]);

	acp->chunk_info[core_id] =
			env_vzalloc(num_chunks * sizeof(acp->chunk_info[0][0]));

	if (!acp->chunk_info[core_id]) {
		ACP_UNLOCK_CHUNKS_WR();
		OCF_DEBUG_PARAM(cache, "failed to allocate acp tables\n");
		return -ENOMEM;
	}

	OCF_DEBUG_PARAM(cache, "successfully allocated acp tables\n");

	/* increment counters */
	acp->num_chunks[core_id] = num_chunks;
	acp->chunks_total += num_chunks;

	for (i = 0; i < acp->num_chunks[core_id]; i++) {
		/* fill in chunk metadata and add to the clean bucket */
		acp->chunk_info[core_id][i].core_id = core_id;
		acp->chunk_info[core_id][i].chunk_id = i;
		list_add(&acp->chunk_info[core_id][i].list,
				&acp->bucket_info[0].chunk_list);
	}

	ACP_UNLOCK_CHUNKS_WR();

	return 0;
}
