/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "cleaning.h"
#include "alru.h"
#include "../metadata/metadata.h"
#include "../utils/utils_cleaner.h"
#include "../utils/utils_user_part.h"
#include "../utils/utils_parallelize.h"
#include "../utils/utils_realloc.h"
#include "../concurrency/ocf_cache_line_concurrency.h"
#include "../ocf_def_priv.h"
#include "cleaning_priv.h"

#define is_alru_head(x) (x == collision_table_entries)
#define is_alru_tail(x) (x == collision_table_entries)

#define OCF_CLEANING_DEBUG 0

#if 1 == OCF_CLEANING_DEBUG

#define OCF_DEBUG_PREFIX "[Clean] %s():%d "

#define OCF_DEBUG_LOG(cache, format, ...) \
	ocf_cache_log_prefix(cache, log_info, OCF_DEBUG_PREFIX, \
			format"\n", __func__, __LINE__, ##__VA_ARGS__)

#define OCF_DEBUG_TRACE(cache) OCF_DEBUG_LOG(cache, "")

#define OCF_DEBUG_MSG(cache, msg) OCF_DEBUG_LOG(cache, "- %s", msg)

#define OCF_DEBUG_PARAM(cache, format, ...) OCF_DEBUG_LOG(cache, "- "format, \
			##__VA_ARGS__)

#else
#define OCF_DEBUG_PREFIX
#define OCF_DEBUG_LOG(cache, format, ...)
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_MSG(cache, msg)
#define OCF_DEBUG_PARAM(cache, format, ...)
#endif

struct alru_flush_ctx {
	struct ocf_cleaner_attribs attribs;
	bool flush_perfomed;
	uint32_t clines_no;
	ocf_cache_t cache;
	ocf_cleaner_end_t cmpl;
	struct flush_data *flush_data;
	size_t flush_data_limit;
};

struct alru_context {
	struct alru_flush_ctx flush_ctx;
	env_spinlock list_lock[OCF_USER_IO_CLASS_MAX];
};


/* -- Start of ALRU functions -- */

/* Appends given sublist to the _head_ of the ALRU list */
static void append_alru_head(ocf_cache_t cache, ocf_part_id_t part_id,
		ocf_cache_line_t head, ocf_cache_line_t tail)
{
	ocf_cache_line_t terminator = cache->device->collision_table_entries;
	struct alru_cleaning_policy *part_alru;
	struct cleaning_policy_meta *meta;
	struct alru_cleaning_policy_meta *old_head;
	struct alru_cleaning_policy_meta *entry;

	part_alru = &cache->user_parts[part_id].clean_pol->policy.alru;

	if (head == terminator && tail == terminator)
		return;

	ENV_BUG_ON(head == terminator);
	ENV_BUG_ON(tail == terminator);

	if (part_alru->lru_head == terminator) {
		part_alru->lru_head = head;
		part_alru->lru_tail = tail;
	} else {
		meta = ocf_metadata_get_cleaning_policy(cache, part_alru->lru_head);
		old_head = &meta->meta.alru;
		old_head->lru_prev = tail;

		meta = ocf_metadata_get_cleaning_policy(cache, tail);
		entry = &meta->meta.alru;
		entry->lru_next = part_alru->lru_head;

		part_alru->lru_head = head;
	}
}

/* Adds the given collision_index to the _head_ of the ALRU list */
static void add_alru_head(ocf_cache_t cache, ocf_part_id_t part_id,
		ocf_cache_line_t cline)
{
	ocf_cache_line_t terminator = cache->device->collision_table_entries;
	struct alru_cleaning_policy *part_alru;
	struct cleaning_policy_meta *meta;
	struct alru_cleaning_policy_meta *entry;

	ENV_BUG_ON(!(cline < terminator));

	ENV_WARN_ON(!metadata_test_dirty(cache, cline));
	ENV_WARN_ON(!metadata_test_valid_any(cache, cline));

	part_alru = &cache->user_parts[part_id].clean_pol->policy.alru;

	meta = ocf_metadata_get_cleaning_policy(cache, cline);
	entry = &meta->meta.alru;
	entry->lru_next = terminator;
	entry->lru_prev = terminator;
	entry->timestamp = env_ticks_to_secs(env_get_tick_count());

	append_alru_head(cache, part_id, cline, cline);

	env_atomic_inc(&part_alru->size);
}

/* Deletes the node with the given collision_index from the ALRU list */
static void remove_alru_list(struct ocf_cache *cache, int partition_id,
		unsigned int collision_index)
{
	uint32_t prev_lru_node, next_lru_node;
	uint32_t collision_table_entries = cache->device->collision_table_entries;
	struct alru_cleaning_policy *part_alru = &cache->user_parts[partition_id]
			.clean_pol->policy.alru;
	struct alru_cleaning_policy_meta *alru;

	ENV_BUG_ON(!(collision_index < collision_table_entries));

	if (env_atomic_read(&part_alru->size) == 0) {
		ocf_cache_log(cache, log_err, "ERROR: Attempt to remove item "
				"from empty ALRU Cleaning Policy queue!\n");
		ENV_BUG();
	}

	alru = &ocf_metadata_get_cleaning_policy(cache, collision_index)
			->meta.alru;
	/* Set prev and next (even if non existent) */
	next_lru_node = alru->lru_next;
	prev_lru_node = alru->lru_prev;

	/* Check if entry is not part of the ALRU list */
	if ((next_lru_node == collision_table_entries) &&
			(prev_lru_node == collision_table_entries) &&
			(part_alru->lru_head != collision_index) &&
			(part_alru->lru_tail != collision_index)) {
		return;
	}

	/* Case 0: If we are head AND tail, there is only one node. So unlink
	 * node and set that there is no node left in the list.
	 */
	if (part_alru->lru_head == collision_index &&
			part_alru->lru_tail == collision_index) {
		alru->lru_next = collision_table_entries;
		alru->lru_prev = collision_table_entries;


		part_alru->lru_head = collision_table_entries;
		part_alru->lru_tail = collision_table_entries;
	}

	/* Case 1: else if this collision_index is ALRU head, but not tail,
	 * update head and return
	 */
	else if ((part_alru->lru_tail != collision_index) &&
			(part_alru->lru_head == collision_index)) {
		struct alru_cleaning_policy_meta *next_alru;

		ENV_BUG_ON(!(next_lru_node < collision_table_entries));

		next_alru = &ocf_metadata_get_cleaning_policy(cache,
				next_lru_node)->meta.alru;

		part_alru->lru_head = next_lru_node;

		alru->lru_next = collision_table_entries;
		next_alru->lru_prev = collision_table_entries;

	}

	/* Case 2: else if this collision_index is ALRU tail, but not head,
	 * update tail and return
	 */
	else if ((part_alru->lru_head != collision_index) &&
			(part_alru->lru_tail == collision_index)) {
		struct alru_cleaning_policy_meta *prev_alru;

		ENV_BUG_ON(!(prev_lru_node < collision_table_entries));

		prev_alru = &ocf_metadata_get_cleaning_policy(cache,
				prev_lru_node)->meta.alru;

		part_alru->lru_tail = prev_lru_node;

		alru->lru_prev = collision_table_entries;
		prev_alru->lru_next = collision_table_entries;

	}

	/* Case 3: else this collision_index is a middle node. There is no
	 * change to the head and the tail pointers.
	 */
	else {
		struct alru_cleaning_policy_meta *prev_alru, *next_alru;

		ENV_BUG_ON(!(next_lru_node < collision_table_entries));
		ENV_BUG_ON(!(prev_lru_node < collision_table_entries));

		prev_alru = &ocf_metadata_get_cleaning_policy(cache,
				prev_lru_node)->meta.alru;
		next_alru = &ocf_metadata_get_cleaning_policy(cache,
				next_lru_node)->meta.alru;
		/* Update prev and next nodes */
		prev_alru->lru_next = alru->lru_next;
		next_alru->lru_prev = alru->lru_prev;

		/* Update the given node */
		alru->lru_next = collision_table_entries;
		alru->lru_prev = collision_table_entries;

	}

	env_atomic_dec(&part_alru->size);
}

static bool is_on_alru_list(struct ocf_cache *cache, int partition_id,
		unsigned int collision_index)
{
	uint32_t prev_lru_node, next_lru_node;
	uint32_t collision_table_entries = cache->device->collision_table_entries;
	struct alru_cleaning_policy *part_alru = &cache->user_parts[partition_id]
			.clean_pol->policy.alru;
	struct alru_cleaning_policy_meta *alru;

	ENV_BUG_ON(!(collision_index < collision_table_entries));

	alru = &ocf_metadata_get_cleaning_policy(cache, collision_index)
			->meta.alru;

	next_lru_node = alru->lru_next;
	prev_lru_node = alru->lru_prev;

	return part_alru->lru_tail == collision_index ||
			part_alru->lru_head == collision_index ||
			next_lru_node != collision_table_entries ||
			prev_lru_node != collision_table_entries;
}


/* -- End of ALRU functions -- */

void cleaning_policy_alru_init_cache_block(struct ocf_cache *cache,
		uint32_t cache_line)
{
	struct alru_cleaning_policy_meta *alru;

	alru = &ocf_metadata_get_cleaning_policy(cache,
			cache_line)->meta.alru;
	alru->timestamp = 0;
	alru->lru_prev = cache->device->collision_table_entries;
	alru->lru_next = cache->device->collision_table_entries;
}

void cleaning_policy_alru_purge_cache_block(struct ocf_cache *cache,
		uint32_t cache_line)
{
	struct alru_context *alru = cache->cleaner.cleaning_policy_context;
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache,
			cache_line);

	env_spinlock_lock(&alru->list_lock[part_id]);
	remove_alru_list(cache, part_id, cache_line);
	env_spinlock_unlock(&alru->list_lock[part_id]);
}

static void __cleaning_policy_alru_purge_cache_block_any(
		struct ocf_cache *cache, uint32_t cache_line)
{
	struct alru_context *ctx = cache->cleaner.cleaning_policy_context;

	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache,
			cache_line);

	env_spinlock_lock(&ctx->list_lock[part_id]);

	if (is_on_alru_list(cache, part_id, cache_line))
		remove_alru_list(cache, part_id, cache_line);

	env_spinlock_unlock(&ctx->list_lock[part_id]);
}

int cleaning_policy_alru_purge_range(struct ocf_cache *cache, int core_id,
		uint64_t start_byte, uint64_t end_byte) {
	struct ocf_user_part *user_part;
	ocf_part_id_t part_id;
	int ret = 0;

	for_each_user_part(cache, user_part, part_id) {
		if (env_atomic_read(&user_part->clean_pol->policy.alru.size) == 0)
			continue;

		ret |= ocf_metadata_actor(cache, part_id,
				core_id, start_byte, end_byte,
				__cleaning_policy_alru_purge_cache_block_any);
	}

	return ret;
}

void cleaning_policy_alru_set_hot_cache_line(struct ocf_cache *cache,
		uint32_t cache_line)
{
	struct alru_context *ctx = cache->cleaner.cleaning_policy_context;
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache,
			cache_line);
	struct alru_cleaning_policy *part_alru = &cache->user_parts[part_id]
			.clean_pol->policy.alru;
	uint32_t prev_lru_node, next_lru_node;
	uint32_t collision_table_entries = cache->device->collision_table_entries;
	struct alru_cleaning_policy_meta *alru;

	ENV_WARN_ON(!metadata_test_dirty(cache, cache_line));
	ENV_WARN_ON(!metadata_test_valid_any(cache, cache_line));

	env_spinlock_lock(&ctx->list_lock[part_id]);

	alru = &ocf_metadata_get_cleaning_policy(cache,
			cache_line)->meta.alru;
	next_lru_node = alru->lru_next;
	prev_lru_node = alru->lru_prev;

	if ((next_lru_node != collision_table_entries) ||
			(prev_lru_node != collision_table_entries) ||
			((part_alru->lru_head == cache_line) &&
			(part_alru->lru_tail == cache_line)))
		remove_alru_list(cache, part_id, cache_line);

	add_alru_head(cache, part_id, cache_line);

	env_spinlock_unlock(&ctx->list_lock[part_id]);
}

static void _alru_rebuild(struct ocf_cache *cache)
{
	struct ocf_user_part *user_part;
	struct alru_cleaning_policy *part_alru;
	ocf_part_id_t part_id;
	ocf_core_id_t core_id;
	ocf_cache_line_t cline;
	uint32_t step = 0;

	for_each_user_part(cache, user_part, part_id) {
		/* ALRU initialization */
		part_alru = &user_part->clean_pol->policy.alru;
		env_atomic_set(&part_alru->size, 0);
		part_alru->lru_head = cache->device->collision_table_entries;
		part_alru->lru_tail = cache->device->collision_table_entries;
		cache->device->runtime_meta->cleaning_thread_access = 0;
	}

	for (cline = 0; cline < cache->device->collision_table_entries; cline++) {
		ocf_metadata_get_core_and_part_id(cache, cline, &core_id,
				NULL);

		OCF_COND_RESCHED_DEFAULT(step);

		if (core_id == OCF_CORE_MAX)
			continue;

		cleaning_policy_alru_init_cache_block(cache, cline);

		if (!metadata_test_dirty(cache, cline))
			continue;

		cleaning_policy_alru_set_hot_cache_line(cache, cline);
	}
}

void cleaning_policy_alru_setup(struct ocf_cache *cache)
{
	struct alru_cleaning_policy_config *config;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_alru].data;

	config->thread_wakeup_time = OCF_ALRU_DEFAULT_WAKE_UP;
	config->stale_buffer_time = OCF_ALRU_DEFAULT_STALENESS_TIME;
	config->flush_max_buffers = OCF_ALRU_DEFAULT_FLUSH_MAX_BUFFERS;
	config->activity_threshold = OCF_ALRU_DEFAULT_ACTIVITY_THRESHOLD;
}

int cleaning_policy_alru_init_common(ocf_cache_t cache)
{
	struct alru_context *ctx;
	int error = 0;
	unsigned i;

	ctx = env_vzalloc(sizeof(*ctx));
	if (!ctx) {
		ocf_cache_log(cache, log_err, "alru context allocation error\n");
		return -OCF_ERR_NO_MEM;
	}

	for (i = 0; i < OCF_USER_IO_CLASS_MAX; i++) {
		error = env_spinlock_init(&ctx->list_lock[i]);
		if (error)
			break;
	}

	if (error) {
		while (i--)
			env_spinlock_destroy(&ctx->list_lock[i]);
		env_vfree(ctx);
		return error;
	}

	cache->device->runtime_meta->cleaning_thread_access = 0;

	cache->cleaner.cleaning_policy_context = ctx;

	return 0;
}

int cleaning_policy_alru_initialize(ocf_cache_t cache, int init_metadata)
{
	int result;

	result = cleaning_policy_alru_init_common(cache);
	if (result)
		return result;

	if (init_metadata)
		_alru_rebuild(cache);

	ocf_kick_cleaner(cache);

	return 0;
}

#define OCF_ALRU_RECOVERY_SHARDS_CNT 32

struct ocf_alru_recovery_context {
	ocf_cache_t cache;
	struct {
		struct {
			ocf_cache_line_t head;
			ocf_cache_line_t tail;
		} part[OCF_USER_IO_CLASS_MAX];
	} shard[OCF_ALRU_RECOVERY_SHARDS_CNT] __attribute__((aligned(64)));

	ocf_cleaning_recovery_end_t cmpl;
	void *priv;
};

static void add_alru_head_recovery(struct ocf_alru_recovery_context *context,
		unsigned shard_id, ocf_core_id_t part_id,
		ocf_cache_line_t cline)
{
	ocf_cache_t cache = context->cache;
	ocf_cache_line_t curr_head, terminator;
	struct cleaning_policy_meta *meta;
	struct alru_cleaning_policy_meta *entry;
	struct alru_cleaning_policy_meta *next;

	terminator = ocf_metadata_collision_table_entries(cache);
	curr_head = context->shard[shard_id].part[part_id].head;

	meta = ocf_metadata_get_cleaning_policy(cache, cline);
	entry = &meta->meta.alru;

	if (curr_head == terminator) {
		/* First node to be added/ */
		entry->lru_next = terminator;
		entry->lru_prev = terminator;
		entry->timestamp = env_ticks_to_secs(env_get_tick_count());

		context->shard[shard_id].part[part_id].head = cline;
		context->shard[shard_id].part[part_id].tail = cline;
	} else {
		/* Not the first node to be added. */
		entry->lru_next = curr_head;
		entry->lru_prev = terminator;
		entry->timestamp = env_ticks_to_secs(env_get_tick_count());

		meta = ocf_metadata_get_cleaning_policy(cache, curr_head);
		next = &meta->meta.alru;

		next->lru_prev = cline;

		context->shard[shard_id].part[part_id].head = cline;
	}
}

static int ocf_alru_recovery_handle(ocf_parallelize_t parallelize,
		void *priv, unsigned shard_id, unsigned shards_cnt)
{
	struct ocf_alru_recovery_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_cache_line_t entries = cache->device->collision_table_entries;
	ocf_cache_line_t terminator = entries;
	unsigned part_size[OCF_USER_IO_CLASS_MAX] = {};
	struct ocf_user_part *user_part;
	struct alru_cleaning_policy *part_alru;
	ocf_part_id_t part_id;
	ocf_core_id_t core_id;
	ocf_cache_line_t cline, portion;
	uint32_t begin, end;
	uint32_t step = 0;
	int i;

	portion = OCF_DIV_ROUND_UP((uint64_t)entries, shards_cnt);
	begin = portion*shard_id;
	end = OCF_MIN((uint64_t)portion*(shard_id + 1), entries);

	for (i = 0; i < OCF_USER_IO_CLASS_MAX; i++) {
		context->shard[shard_id].part[i].head = terminator;
		context->shard[shard_id].part[i].tail = terminator;
	}

	for (cline = begin; cline < end; cline++) {
		ocf_metadata_get_core_and_part_id(cache, cline,
				&core_id, &part_id);

		OCF_COND_RESCHED_DEFAULT(step);

		if (core_id == OCF_CORE_MAX)
			continue;

		if (!metadata_test_dirty(cache, cline)) {
			cleaning_policy_alru_init_cache_block(cache, cline);
		} else {
			add_alru_head_recovery(context, shard_id,
					part_id, cline);
			++part_size[part_id];
		}
	}

	for_each_user_part(cache, user_part, part_id) {
		part_alru = &user_part->clean_pol->policy.alru;
		env_atomic_add(part_size[part_id], &part_alru->size);
	}

	return 0;
}

static void ocf_alru_recovery_finish(ocf_parallelize_t parallelize,
		void *priv, int error)
{
	struct ocf_alru_recovery_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_part_id_t part_id;
	ocf_cache_line_t head, tail;
	unsigned shard;

	if (error)
		goto end;

	for (part_id = 0; part_id < OCF_USER_IO_CLASS_MAX; part_id++) {
		for (shard = 0; shard < OCF_ALRU_RECOVERY_SHARDS_CNT; shard++) {
			head = context->shard[shard].part[part_id].head;
			tail = context->shard[shard].part[part_id].tail;

			append_alru_head(cache, part_id, head, tail);
		}
	}

	ocf_kick_cleaner(cache);

end:
	context->cmpl(context->priv, error);

	ocf_parallelize_destroy(parallelize);
}

void cleaning_policy_alru_recovery(ocf_cache_t cache,
		ocf_cleaning_recovery_end_t cmpl, void *priv)
{
	struct ocf_alru_recovery_context *context;
	ocf_parallelize_t parallelize;
	struct alru_cleaning_policy *part_alru;
	struct ocf_user_part *user_part;
	ocf_part_id_t part_id;
	int result;

	result = ocf_parallelize_create(&parallelize, cache,
			OCF_ALRU_RECOVERY_SHARDS_CNT, sizeof(*context),
			ocf_alru_recovery_handle, ocf_alru_recovery_finish);
	if (result) {
		cmpl(priv, result);
		return;
	}


	result = cleaning_policy_alru_init_common(cache);
	if (result) {
		ocf_parallelize_destroy(parallelize);
		cmpl(priv, result);
		return;
	}

	for_each_user_part(cache, user_part, part_id) {
		/* ALRU initialization */
		part_alru = &user_part->clean_pol->policy.alru;
		env_atomic_set(&part_alru->size, 0);
		part_alru->lru_head = cache->device->collision_table_entries;
		part_alru->lru_tail = cache->device->collision_table_entries;
		cache->device->runtime_meta->cleaning_thread_access = 0;
	}

	context = ocf_parallelize_get_priv(parallelize);
	context->cache = cache;
	context->cmpl = cmpl;
	context->priv = priv;

	ocf_parallelize_run(parallelize);
}

void cleaning_policy_alru_deinitialize(struct ocf_cache *cache)
{
	struct alru_context *alru = cache->cleaner.cleaning_policy_context;
	unsigned i;

	for (i = 0; i < OCF_USER_IO_CLASS_MAX; i++)
		env_spinlock_destroy(&alru->list_lock[i]);

	env_vfree(cache->cleaner.cleaning_policy_context);
	cache->cleaner.cleaning_policy_context = NULL;
}

int cleaning_policy_alru_set_cleaning_param(ocf_cache_t cache,
		uint32_t param_id, uint32_t param_value)
{
	struct alru_cleaning_policy_config *config;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_alru].data;

	switch (param_id) {
	case ocf_alru_wake_up_time:
		OCF_CLEANING_CHECK_PARAM(cache, param_value,
				OCF_ALRU_MIN_WAKE_UP,
				OCF_ALRU_MAX_WAKE_UP,
				"thread_wakeup_time");
		config->thread_wakeup_time = param_value;
		ocf_cache_log(cache, log_info, "Write-back flush thread "
			"wake-up time: %d\n", config->thread_wakeup_time);
		ocf_kick_cleaner(cache);
		break;
	case ocf_alru_stale_buffer_time:
		OCF_CLEANING_CHECK_PARAM(cache, param_value,
				OCF_ALRU_MIN_STALENESS_TIME,
				OCF_ALRU_MAX_STALENESS_TIME,
				"stale_buffer_time");
		config->stale_buffer_time = param_value;
		ocf_cache_log(cache, log_info, "Write-back flush thread "
			"staleness time: %d\n", config->stale_buffer_time);
		break;
	case ocf_alru_flush_max_buffers:
		OCF_CLEANING_CHECK_PARAM(cache, param_value,
				OCF_ALRU_MIN_FLUSH_MAX_BUFFERS,
				OCF_ALRU_MAX_FLUSH_MAX_BUFFERS,
				"flush_max_buffers");
		config->flush_max_buffers = param_value;
		ocf_cache_log(cache, log_info, "Write-back flush thread max "
				"buffers flushed per iteration: %d\n",
				config->flush_max_buffers);
		break;
	case ocf_alru_activity_threshold:
		OCF_CLEANING_CHECK_PARAM(cache, param_value,
				OCF_ALRU_MIN_ACTIVITY_THRESHOLD,
				OCF_ALRU_MAX_ACTIVITY_THRESHOLD,
				"activity_threshold");
		config->activity_threshold = param_value;
		ocf_cache_log(cache, log_info, "Write-back flush thread "
				"activity time threshold: %d\n",
				config->activity_threshold);
		break;
	default:
		return -OCF_ERR_INVAL;
	}

	return 0;
}

int cleaning_policy_alru_get_cleaning_param(ocf_cache_t cache,
		uint32_t param_id, uint32_t *param_value)
{
	struct alru_cleaning_policy_config *config;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_alru].data;

	switch (param_id) {
	case ocf_alru_wake_up_time:
		*param_value = config->thread_wakeup_time;
		break;
	case ocf_alru_stale_buffer_time:
		*param_value = config->stale_buffer_time;
		break;
	case ocf_alru_flush_max_buffers:
		*param_value = config->flush_max_buffers;
		break;
	case ocf_alru_activity_threshold:
		*param_value = config->activity_threshold;
		break;
	default:
		return -OCF_ERR_INVAL;
	}

	return 0;
}

static inline uint32_t compute_timestamp(
		const struct alru_cleaning_policy_config *config)
{
	unsigned long time;

	time = env_get_tick_count();
	time -= env_secs_to_ticks(config->stale_buffer_time);
	time = env_ticks_to_secs(time);

	return (uint32_t) time;
}

static int check_for_io_activity(struct ocf_cache *cache,
		struct alru_cleaning_policy_config *config)
{
	unsigned int now, last;

	now = env_ticks_to_msecs(env_get_tick_count());
	last = env_atomic_read(&cache->last_access_ms);

	if ((now - last) < config->activity_threshold)
		return 1;
	return 0;
}

static bool clean_later(ocf_cache_t cache, uint32_t *delta)
{
	struct alru_cleaning_policy_config *config;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_alru].data;

	*delta = env_ticks_to_secs(env_get_tick_count()) -
			cache->device->runtime_meta->cleaning_thread_access;
	if (*delta <= config->thread_wakeup_time)
		return true;

	return false;
}

static bool is_cleanup_possible(ocf_cache_t cache)
{
	struct alru_cleaning_policy_config *config;
	uint32_t delta;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_alru].data;

	if (check_for_io_activity(cache, config)) {
		OCF_DEBUG_PARAM(cache, "IO activity detected");
		return false;
	}

	if (clean_later(cache, &delta)) {
		OCF_DEBUG_PARAM(cache,
			"Cleaning policy configured to clean later "
			"delta=%u wake_up=%u", delta,
			config->thread_wakeup_time);
		return false;
	}

	//Cleaning policy configured to not clean anything
	if (config->flush_max_buffers == 0)
		return false;

	return true;
}

static void get_block_to_flush(struct flush_data* dst,
		ocf_cache_line_t cache_line, struct ocf_cache* cache)
{
	ocf_core_id_t core_id;
	uint64_t core_line;

	ocf_metadata_get_core_info(cache, cache_line,
			&core_id, &core_line);

	dst->cache_line = cache_line;
	dst->core_id = core_id;
	dst->core_line = core_line;
}

static bool more_blocks_to_flush(struct ocf_cache *cache,
		ocf_cache_line_t cache_line, uint32_t last_access)
{
	struct alru_cleaning_policy_meta *alru;

	if (cache_line >= cache->device->collision_table_entries)
		return false;

	alru = &ocf_metadata_get_cleaning_policy(cache,
			cache_line)->meta.alru;
	if (alru->timestamp >= last_access)
		return false;

	return true;
}

static bool block_is_busy(struct ocf_cache *cache,
		ocf_cache_line_t cache_line)
{
	ocf_core_id_t core_id;
	uint64_t core_line;

	ocf_metadata_get_core_info(cache, cache_line,
			&core_id, &core_line);

	if (!cache->core[core_id].opened)
		return true;

	if (ocf_cache_line_is_used(ocf_cache_line_concurrency(cache),
			cache_line)) {
		return true;
	}

	return false;
}

static int get_data_to_flush(struct alru_context *ctx)
{
	struct alru_flush_ctx *fctx = &ctx->flush_ctx;
	ocf_cache_t cache = fctx->cache;
	struct alru_cleaning_policy_config *config;
	struct alru_cleaning_policy_meta *alru;
	ocf_cache_line_t cache_line;
	struct ocf_user_part *user_part;
	uint32_t last_access;
	int to_flush = 0;
	int part_id = OCF_IO_CLASS_ID_MAX;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_alru].data;

	for_each_user_part(cache, user_part, part_id) {
		env_spinlock_lock(&ctx->list_lock[part_id]);

		cache_line = user_part->clean_pol->policy.alru.lru_tail;

		last_access = compute_timestamp(config);

		#if OCF_CLEANING_DEBUG == 1
		alru = &ocf_metadata_get_cleaning_policy(cache, cache_line)
				->meta.alru;
		OCF_DEBUG_PARAM(cache, "Last access=%u, timestamp=%u rel=%d",
				last_access, alru->timestamp,
				alru->timestamp < last_access);
		#endif

		while (more_blocks_to_flush(cache, cache_line, last_access)) {
			if (to_flush >= fctx->clines_no) {
				env_spinlock_unlock(&ctx->list_lock[part_id]);
				goto end;
			}

			if (!block_is_busy(cache, cache_line)) {
				get_block_to_flush(&fctx->flush_data[to_flush], cache_line,
						cache);
				to_flush++;
			}

			alru = &ocf_metadata_get_cleaning_policy(cache,
					cache_line)->meta.alru;
			cache_line = alru->lru_prev;
		}

		env_spinlock_unlock(&ctx->list_lock[part_id]);
	}

end:
	OCF_DEBUG_PARAM(cache, "Collected items_to_clean=%u", to_flush);

	return to_flush;
}

static void alru_clean_complete(void *priv, int err)
{
	struct alru_cleaning_policy_config *config;
	struct alru_flush_ctx *fctx = priv;
	ocf_cache_t cache = fctx->cache;
	int interval;

	OCF_REALLOC_DEINIT(&fctx->flush_data, &fctx->flush_data_limit);

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_alru].data;

	interval = fctx->flush_perfomed ? 0 : config->thread_wakeup_time * 1000;

	fctx->cmpl(&fctx->cache->cleaner, interval);
}

static void alru_clean(struct alru_context *ctx)
{
	struct alru_flush_ctx *fctx = &ctx->flush_ctx;
	ocf_cache_t cache = fctx->cache;
	int to_clean;

	if (!is_cleanup_possible(cache)) {
		alru_clean_complete(fctx, 0);
		return;
	}

	if (ocf_metadata_try_start_exclusive_access(&cache->metadata.lock)) {
		alru_clean_complete(fctx, 0);
		return;
	}

	OCF_REALLOC(&fctx->flush_data, sizeof(fctx->flush_data[0]),
			fctx->clines_no, &fctx->flush_data_limit);
	if (!fctx->flush_data) {
		ocf_cache_log(cache, log_warn, "No memory to allocate flush "
				"data for ALRU cleaning policy");
		goto end;
	}

	to_clean = get_data_to_flush(ctx);
	if (to_clean > 0) {
		fctx->flush_perfomed = true;
		ocf_cleaner_do_flush_data_async(cache, fctx->flush_data, to_clean,
				&fctx->attribs);
		ocf_metadata_end_exclusive_access(&cache->metadata.lock);
		return;
	}

	/* Update timestamp only if there are no items to be cleaned */
	cache->device->runtime_meta->cleaning_thread_access =
		env_ticks_to_secs(env_get_tick_count());

end:
	ocf_metadata_end_exclusive_access(&cache->metadata.lock);
	alru_clean_complete(fctx, 0);
}

void cleaning_alru_perform_cleaning(ocf_cache_t cache, ocf_cleaner_end_t cmpl)
{
	struct alru_context *ctx = cache->cleaner.cleaning_policy_context;
	struct alru_flush_ctx *fctx = &ctx->flush_ctx;
	struct alru_cleaning_policy_config *config;

	config = (void *)&cache->conf_meta->cleaning[ocf_cleaning_alru].data;

	OCF_REALLOC_INIT(&fctx->flush_data, &fctx->flush_data_limit);

	fctx->attribs.cmpl_context = fctx;
	fctx->attribs.cmpl_fn = alru_clean_complete;
	fctx->attribs.lock_cacheline = true;
	fctx->attribs.lock_metadata = false;
	fctx->attribs.do_sort = true;
	fctx->attribs.io_queue = cache->cleaner.io_queue;
	fctx->attribs.cmpl_queue = true;

	fctx->clines_no = config->flush_max_buffers;
	fctx->cache = cache;
	fctx->cmpl = cmpl;
	fctx->flush_perfomed = false;

	alru_clean(ctx);
}
