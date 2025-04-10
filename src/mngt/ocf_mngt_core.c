/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_env.h"
#include "ocf_mngt_common.h"
#include "ocf_mngt_core_priv.h"
#include "../ocf_priv.h"
#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../utils/utils_pipeline.h"
#include "../utils/utils_cleaner.h"
#include "../ocf_stats_priv.h"
#include "../ocf_def_priv.h"
#include "../cleaning/cleaning_ops.h"
#include "../prefetch/ocf_prefetch.h"
#include "../classifier/ocf_classifier.h"

ocf_seq_no_t ocf_mngt_get_core_seq_no(ocf_cache_t cache)
{
	if (cache->conf_meta->curr_core_seq_no == OCF_SEQ_NO_MAX)
		return OCF_SEQ_NO_INVALID;

	return ++cache->conf_meta->curr_core_seq_no;
}

static int ocf_mngt_core_set_name(ocf_core_t core, const char *name)
{
	return env_strncpy(core->conf_meta->name, OCF_CORE_NAME_SIZE,
			name, OCF_CORE_NAME_SIZE);
}

static int ocf_core_get_by_uuid(ocf_cache_t cache, ocf_uuid_t uuid,
		ocf_core_t *core)
{
	struct ocf_volume *volume;
	ocf_core_t i_core;
	ocf_core_id_t i_core_id;
	int diff, result;

	for_each_core_metadata(cache, i_core, i_core_id) {
		volume = ocf_core_get_volume(i_core);

		result = ocf_uuid_compare(&volume->uuid, uuid, &diff);

		if (result)
			return -OCF_ERR_UNKNOWN;

		if (diff == 0) {
			*core = i_core;
			return 0;
		}
	}

	return -OCF_ERR_CORE_NOT_EXIST;
}

static int _ocf_uuid_set(const struct ocf_volume_uuid *uuid,
		struct ocf_metadata_uuid *muuid)
{
	int result;

	if (!uuid->data)
		return -EINVAL;

	if (uuid->size > sizeof(muuid->data))
		return -ENOBUFS;

	result = env_memcpy(muuid->data, sizeof(muuid->data),
			uuid->data, uuid->size);
	if (result)
		return result;

	if (uuid->size < sizeof(muuid->data)) {
		result = env_memset(muuid->data + uuid->size,
				sizeof(muuid->data) - uuid->size, 0);
		if (result)
			return result;
	}

	muuid->size = uuid->size;

	return 0;
}

static int ocf_mngt_core_set_uuid_metadata(ocf_core_t core,
		const struct ocf_volume_uuid *uuid,
		struct ocf_volume_uuid *new_uuid)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	struct ocf_metadata_uuid *muuid = ocf_metadata_get_core_uuid(cache,
						ocf_core_get_id(core));

	if (_ocf_uuid_set(uuid, muuid))
		return -ENOBUFS;

	if (new_uuid) {
		new_uuid->data = muuid->data;
		new_uuid->size = muuid->size;
	}

	return 0;
}

void ocf_mngt_core_clear_uuid_metadata(ocf_core_t core)
{
	struct ocf_volume_uuid uuid = { .size = 0, };

	ocf_mngt_core_set_uuid_metadata(core, &uuid, NULL);
}

struct ocf_cache_add_core_context {
	ocf_mngt_cache_add_core_end_t cmpl;
	void *priv;
	ocf_pipeline_t pipeline;
	struct ocf_mngt_core_config cfg;
	ocf_cache_t cache;
	ocf_core_t core;

	struct {
		bool uuid_set : 1;
		bool volume_inited : 1;
		bool volume_opened : 1;
		bool clean_pol_added : 1;
		bool counters_allocated : 1;
		bool cutoff_initialized: 1;
	} flags;
};

static void _ocf_mngt_cache_add_core_handle_error(
		struct ocf_cache_add_core_context *context)
{
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;
	ocf_core_id_t core_id;
	ocf_volume_t volume;

	if (!core)
		return;

	core_id = ocf_core_get_id(core);
	volume = core->volume;

	if (context->flags.counters_allocated) {
		env_bit_clear(core_id,
				cache->conf_meta->valid_core_bitmap);
		cache->conf_meta->core_count--;
		core->conf_meta->valid = false;
		core->added = false;
		core->opened = false;

		env_free(core->counters);
		core->counters = NULL;
	}

	if (context->flags.clean_pol_added)
		ocf_cleaning_remove_core(cache, core_id);

	if (context->flags.cutoff_initialized)
		ocf_core_seq_cutoff_deinit(core);

	if (context->flags.volume_opened)
		ocf_volume_close(volume);

	if (context->flags.volume_inited) {
		ocf_volume_destroy(volume);
		core->volume = NULL;
	}

	if (context->flags.uuid_set)
		ocf_mngt_core_clear_uuid_metadata(core);
}

static unsigned long _ffz(unsigned long word)
{
	int i;

	for (i = 0; i < sizeof(word)*8 && (word & 1); i++)
		word >>= 1;

	return i;
}

static unsigned long _ocf_mngt_find_first_free_core(const unsigned long *bitmap)
{
	unsigned long i;
	unsigned long ret = OCF_CORE_MAX;

	/* check core 0 availability */
	bool zero_core_free = !(*bitmap & 0x1UL);

	/* check if any core id is free except 0 */
	for (i = 0; i * sizeof(unsigned long) * 8 < OCF_CORE_MAX; i++) {
		unsigned long long ignore_mask = (i == 0) ? 1UL : 0UL;
		if (~(bitmap[i] | ignore_mask)) {
			ret = OCF_MIN(OCF_CORE_MAX, i * sizeof(unsigned long) *
					8 + _ffz(bitmap[i] | ignore_mask));
			break;
		}
	}

	/* return 0 only if no other core is free */
	if (ret == OCF_CORE_MAX && zero_core_free)
		return 0;

	return ret;
}

static int ocf_mngt_find_free_core(ocf_cache_t cache, ocf_core_t *core)
{
	ocf_core_id_t core_id;
	ocf_core_t tmp_core;

	core_id = _ocf_mngt_find_first_free_core(
			cache->conf_meta->valid_core_bitmap);

	tmp_core = ocf_cache_get_core(cache, core_id);
	if (!tmp_core)
		return -OCF_ERR_TOO_MANY_CORES;

	*core = tmp_core;

	return 0;
}

struct ocf_mngt_min_io_size_detect_context {
	ocf_mngt_core_min_io_size_detect_end_t cmpl;
	ocf_pipeline_t pipeline;
	struct ocf_request *req;
	void *priv;
	uint32_t min_io_size;
};

static void ocf_mngt_core_min_io_size_detect_step_complete(
		struct ocf_request *req, int error)
{
	struct ocf_mngt_min_io_size_detect_context *context = req->priv;

	/* In case of failure - try next one */
	if (error)
		OCF_PL_NEXT_RET(context->pipeline);

	context->min_io_size = req->bytes;
	OCF_PL_FINISH_RET(context->pipeline, 0);
}

static void ocf_mngt_core_min_io_size_detect_step(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_min_io_size_detect_context *context = priv;
	uint32_t bytes = ocf_pipeline_arg_get_int(arg);
	struct ocf_request *req = context->req;

	req->core_forward_end = ocf_mngt_core_min_io_size_detect_step_complete;
	req->bytes = bytes;
	req->priv = context;
	ocf_req_forward_core_io(req, OCF_READ, 0, bytes, 0);
}

#define MIN_DETECT_SIZE (1 << ENV_SECTOR_SHIFT)
#define MAX_DETECT_SIZE (MIN_DETECT_SIZE << 7)

static void ocf_mngt_core_min_io_size_detect_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_mngt_min_io_size_detect_context *context = priv;
	ocf_core_t core = context->req->core;
	ocf_cache_t cache = context->req->cache;
	ocf_ctx_t ctx = ocf_cache_get_ctx(cache);

	ctx_data_free(ctx, context->req->data);
	ocf_req_put(context->req);

	if (context->min_io_size == 0)
		error = -OCF_ERR_IO;

	if (!error) {
		core->minimal_io_size = context->min_io_size;
		ocf_core_log(core, log_info, "Detected minimal io size of %u B\n",
			core->minimal_io_size);
	} else {
		core->minimal_io_size = MIN_DETECT_SIZE;
		ocf_core_log(core, log_warn, "Fail to detect minimal IO size up to %u,"
			   " fallback to %u\n", MAX_DETECT_SIZE, MIN_DETECT_SIZE);
		ocf_core_log(core, log_warn, "Swap detection is disabled due to minimal"
			   " IO size detecion failure\n");
	}

	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_arg ocf_mngt_core_min_io_size_detect_args[] = {
	OCF_PL_ARG_INT(MIN_DETECT_SIZE),
	OCF_PL_ARG_INT(MIN_DETECT_SIZE << 1),
	OCF_PL_ARG_INT(MIN_DETECT_SIZE << 2),
	OCF_PL_ARG_INT(MIN_DETECT_SIZE << 3),
	OCF_PL_ARG_INT(MIN_DETECT_SIZE << 4),
	OCF_PL_ARG_INT(MIN_DETECT_SIZE << 5),
	OCF_PL_ARG_INT(MIN_DETECT_SIZE << 6),
	OCF_PL_ARG_INT(MIN_DETECT_SIZE << 7),
	OCF_PL_ARG_TERMINATOR(),
};

struct ocf_pipeline_properties ocf_mngt_core_min_io_size_detect_pl_props = {
        .priv_size = sizeof(struct ocf_mngt_min_io_size_detect_context),
        .finish = ocf_mngt_core_min_io_size_detect_finish,
        .steps = {
		OCF_PL_STEP_FOREACH(ocf_mngt_core_min_io_size_detect_step,
				ocf_mngt_core_min_io_size_detect_args),
                OCF_PL_STEP_TERMINATOR(),
        },
};

void ocf_mngt_core_min_io_size_detect(ocf_core_t core,
		ocf_mngt_core_min_io_size_detect_end_t cmpl, void *priv)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_ctx_t ctx = ocf_cache_get_ctx(cache);
	struct ocf_mngt_min_io_size_detect_context *context;
	ocf_pipeline_t pipeline;
	int result;

	if (ocf_cache_ml_is_upper(cache)) {
		cmpl(priv, 0);
		return;
	}

	result = ocf_pipeline_create(&pipeline, ocf_core_get_cache(core),
			&ocf_mngt_core_min_io_size_detect_pl_props);
	if (result)
		OCF_CMPL_RET(priv, result);

	context = ocf_pipeline_get_priv(pipeline);

	context->req = ocf_req_new_mngt(cache, cache->mngt_queue);
	if (!context->req) {
		ocf_pipeline_destroy(pipeline);
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);
	}

	context->req->data = ctx_data_alloc(ctx,
			BYTES_TO_PAGES(MAX_DETECT_SIZE));
	if (!context->req->data) {
		ocf_req_put(context->req);
		ocf_pipeline_destroy(pipeline);
		OCF_CMPL_RET(priv, -OCF_ERR_NO_MEM);
	}

	context->req->core = core;

	context->cmpl = cmpl;
	context->priv = priv;
	context->min_io_size = 0;
	context->pipeline = pipeline;

	ocf_pipeline_next(pipeline);
}

int ocf_mngt_core_init_front_volume(ocf_core_t core)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_volume_type_t type;
	struct ocf_core_volume_uuid core_uuid = {0};
	struct ocf_volume_uuid uuid = {
		.data = &core_uuid,
		.size = sizeof(core_uuid),
	};
	int ret;

	ret = ocf_core_get_front_uuid(core, &core_uuid);
	if (ret)
		return ret;

	type = ocf_ctx_get_volume_type_internal(cache->owner,
			OCF_VOLUME_TYPE_CORE);
	if (!type)
		return -OCF_ERR_INVAL;

	ret = ocf_volume_init(&core->front_volume, type, &uuid, true);
	if (ret)
		return ret;

	core->front_volume.cache = cache;

	return ret;
}

int ocf_mngt_core_init_prefetch(ocf_core_t core)
{
	ocf_prefetch_create(core);

	#define X(classifier)	ocf_classifier_create_##classifier(core);
	OCF_CLASSIFIER_HANDLERS_X
	#undef X

	return 0;
}

static void ocf_mngt_cache_try_add_core_prepare(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_add_core_context *context = priv;
	struct ocf_mngt_core_config *cfg = &context->cfg;
	ocf_cache_t cache = context->cache;
	ocf_core_t core;
	ocf_volume_t volume;
	ocf_volume_type_t type;
	ocf_ctx_t ctx = cache->owner;
	int result, diff;

	result = ocf_core_get_by_name(cache, cfg->name,
				OCF_CORE_NAME_SIZE, &core);
	if (result)
		goto err;

	if (core->opened) {
		ocf_cache_log(cache, log_err, "Core already opened\n");
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_CORE_UUID_EXISTS);
	}

	volume = ocf_core_get_volume(core);
	type = ocf_volume_get_type(volume);

	if (ocf_ctx_get_volume_type_id(ctx, type) != cfg->volume_type) {
		result = -OCF_ERR_INVAL_VOLUME_TYPE;
		goto err;
	}

	result = ocf_uuid_compare(&volume->uuid, &cfg->uuid, &diff);
	if (result | diff) {
		result = -OCF_ERR_INVAL;
		goto err;
	}

	context->core = core;

	OCF_PL_NEXT_RET(pipeline);

err:
	ocf_cache_log(cache, log_err, "Core with given uuid not found "
			"in cache metadata\n");
	OCF_PL_FINISH_RET(pipeline, result);
}

static void ocf_mngt_cache_try_add_core_insert(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_add_core_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;
	ocf_volume_t volume;
	int result;

	ocf_core_log(core, log_debug, "Inserting core\n");

	volume = ocf_core_get_volume(core);
	volume->cache = cache;

	result = ocf_volume_open(volume, NULL);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);

	if (ocf_volume_get_length(volume) != core->conf_meta->length) {
		ocf_cache_log(cache, log_err,
				"Size of core volume doesn't match with"
				" the size stored in cache metadata!\n");
		result = -OCF_ERR_CORE_SIZE_MISMATCH;
		goto error_after_open;
	}

	core->opened = true;

	if (!(--cache->ocf_core_inactive_count))
		env_bit_clear(ocf_cache_state_incomplete, &cache->cache_state);

	OCF_PL_NEXT_RET(pipeline);

error_after_open:
	ocf_volume_close(volume);
	OCF_PL_FINISH_RET(pipeline, result);
}

static void ocf_mngt_cache_add_core_prepare(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_add_core_context *context = priv;
	struct ocf_mngt_core_config *cfg = &context->cfg;
	ocf_cache_t cache = context->cache;
	ocf_core_t core;
	int result;

	result = ocf_core_get_by_name(cache, cfg->name,
				OCF_CACHE_NAME_SIZE, &core);
	if (!result)
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_CORE_EXIST);

	result = ocf_core_get_by_uuid(cache, &cfg->uuid, &core);
	if (!result)
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_CORE_UUID_EXISTS);
	else if (result != -OCF_ERR_CORE_NOT_EXIST)
		OCF_PL_FINISH_RET(context->pipeline, result);

	result = ocf_mngt_find_free_core(cache, &core);
	if (result)
		OCF_PL_FINISH_RET(context->pipeline, result);

	context->core = core;

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_cache_add_core_flush_sb_complete(void *priv, int error)
{
	struct ocf_cache_add_core_context *context = priv;

	if (error)
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_WRITE_CACHE);

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_add_core_insert(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_add_core_context *context = priv;
	struct ocf_mngt_core_config *cfg = &context->cfg;
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;
	ocf_core_id_t core_id;
	struct ocf_volume_uuid new_uuid;
	ocf_volume_t volume;
	ocf_volume_type_t type;
	ocf_seq_no_t core_sequence_no = 0;
	uint64_t length;
	int i, result = 0;

	ocf_cache_log(cache, log_debug, "Inserting core %s\n", cfg->name);

	core->cache = cache;
	core_id = ocf_core_get_id(core);

	result = ocf_mngt_core_set_name(core, cfg->name);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);

	/* Set uuid */
	result = ocf_mngt_core_set_uuid_metadata(core, &cfg->uuid, &new_uuid);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);

	context->flags.uuid_set = true;

	type = ocf_ctx_get_volume_type_internal(cache->owner, cfg->volume_type);
	if (!type)
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_INVAL_VOLUME_TYPE);

	result = ocf_volume_create(&core->volume, type, NULL);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);
	volume = core->volume;
	ocf_volume_set_uuid(volume, &new_uuid);
	volume->cache = cache;

	/* set per core config to the global value of the cache object */
	core->ocf_classifier = cache->ocf_classifier;
	core->ocf_prefetcher = cache->ocf_prefetcher;
	core->has_volume = true;
	context->flags.volume_inited = true;

	if (cfg->user_metadata.data && cfg->user_metadata.size > 0) {
		result = ocf_mngt_core_set_user_metadata(core,
				cfg->user_metadata.data,
				cfg->user_metadata.size);
		if (result)
			OCF_PL_FINISH_RET(pipeline, result);
	}

	result = ocf_volume_open(volume, cfg->volume_params);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);

	context->flags.volume_opened = true;

	length = ocf_volume_get_length(volume);
	if (!length) {
		ocf_cache_log(cache, log_err, "Core %s is zero size\n", cfg->name);
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_CORE_NOT_AVAIL);
	}
	if (length > ((1ULL << CORE_LINE_BITS)) * ocf_line_size(cache)) {
		ocf_cache_log(cache, log_err, "Core %s is too large: length is %" ENV_PRIu64
				", max supported is %llu\n", cfg->name,
				length, (1ULL << CORE_LINE_BITS) * ocf_line_size(cache));
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_CORE_NOT_AVAIL);
	}

	core->conf_meta->length = length;
	core->conf_meta->type = cfg->volume_type;

	if (ocf_cache_is_device_attached(cache)) {
		result = ocf_cleaning_add_core(cache, core_id);
		if (result)
			OCF_PL_FINISH_RET(pipeline, result);

		context->flags.clean_pol_added = true;
	}

	result = ocf_core_seq_cutoff_init(core);
	if (result)
		OCF_PL_FINISH_RET(pipeline, result);
	context->flags.cutoff_initialized = true;

	/* When adding new core to cache, allocate stat counters */
	core->counters =
		env_zalloc(sizeof(*core->counters), ENV_MEM_NORMAL);
	if (!core->counters)
		OCF_PL_FINISH_RET(context->pipeline, -OCF_ERR_NO_MEM);

	context->flags.counters_allocated = true;

	/* When adding new core to cache, reset all core/cache statistics */
	ocf_core_stats_initialize(core);
	env_atomic_set(&core->runtime_meta->cached_clines, 0);
	env_atomic_set(&core->runtime_meta->dirty_clines, 0);
	env_atomic64_set(&core->runtime_meta->dirty_since, 0);

	for (i = 0; i != OCF_USER_IO_CLASS_MAX; i++) {
		env_atomic_set(&core->runtime_meta->
				part_counters[i].cached_clines, 0);
		env_atomic_set(&core->runtime_meta->
				part_counters[i].dirty_clines, 0);
	}

	/* In metadata mark data this core was added into cache */
	env_bit_set(core_id, cache->conf_meta->valid_core_bitmap);
	context->cache->conf_meta->core_count++;

	core->conf_meta->valid = true;
	core->added = true;
	core->opened = true;

	/* Set default cache parameters for sequential */
	env_atomic_set(&core->conf_meta->seq_cutoff_policy,
			ocf_seq_cutoff_policy_default);
	env_atomic_set(&core->conf_meta->seq_cutoff_threshold,
			cfg->seq_cutoff_threshold);
	env_atomic_set(&core->conf_meta->seq_cutoff_promo_count,
			cfg->seq_cutoff_promotion_count);
	env_atomic_set(&core->conf_meta->seq_cutoff_promote_on_threshold,
			cfg->seq_cutoff_promote_on_threshold);

	/* Add core sequence number for atomic metadata matching */
	if (ocf_cache_is_device_attached(cache) &&
			ocf_volume_is_atomic(&cache->device->volume)) {
		core_sequence_no = ocf_mngt_get_core_seq_no(cache);
		if (core_sequence_no == OCF_SEQ_NO_INVALID)
			OCF_PL_FINISH_RET(pipeline, -OCF_ERR_TOO_MANY_CORES);
	}

	core->conf_meta->seq_no = core_sequence_no;

	/* Update super-block with core device addition */

	if (!ocf_cache_is_device_attached(cache)) {
		if (!cache->metadata.is_volatile) {
			ocf_cache_log(cache, log_warn, "Cache is in detached state. "
					"The changes about the new core won't persist cache stop "
					"unless a cache volume is attached\n");
		}
		OCF_PL_NEXT_RET(pipeline);
	}

	core->minimal_io_size = 0;

	ocf_metadata_flush_superblock(cache,
			_ocf_mngt_cache_add_core_flush_sb_complete, context);
}

static void ocf_mngt_cache_add_core_init_front_volume(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_add_core_context *context = priv;
	int result;

	result = ocf_mngt_core_init_front_volume(context->core);

	OCF_PL_NEXT_ON_SUCCESS_RET(pipeline, result);
}

static void ocf_mngt_cache_add_core_init_prefetch(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_add_core_context *context = priv;
	int result;

	result = ocf_mngt_core_init_prefetch(context->core);

	OCF_PL_NEXT_ON_SUCCESS_RET(pipeline, result);
}

static void _ocf_mngt_add_core_minimal_io_size_detection_callback(
		void *ctx, int error)
{
	struct ocf_cache_add_core_context *add_core_context = ctx;

	OCF_PL_NEXT_ON_SUCCESS_RET(add_core_context->pipeline, error);
}

static void ocf_mngt_cache_add_core_detect_min_io_size(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_add_core_context *context = priv;

	ocf_mngt_core_min_io_size_detect(context->core,
			_ocf_mngt_add_core_minimal_io_size_detection_callback,
			context);
}

static void ocf_mngt_cache_add_core_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_cache_add_core_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;

	if (error) {
		_ocf_mngt_cache_add_core_handle_error(context);
		ocf_cache_log(cache, log_err, "Adding core %s failed\n",
				context->cfg.name);
		goto out;
	}

	ocf_core_log(core, log_info, "Successfully added\n");

out:
	context->cmpl(cache, core, context->priv, error);
	env_vfree(context->cfg.uuid.data);
	ocf_pipeline_destroy(context->pipeline);
}

struct ocf_pipeline_properties ocf_mngt_cache_try_add_core_pipeline_props = {
	.priv_size = sizeof(struct ocf_cache_add_core_context),
	.finish = ocf_mngt_cache_add_core_finish,
	.steps = {
		OCF_PL_STEP(ocf_mngt_cache_try_add_core_prepare),
		OCF_PL_STEP(ocf_mngt_cache_try_add_core_insert),
		OCF_PL_STEP(ocf_mngt_cache_add_core_init_front_volume),
		OCF_PL_STEP(ocf_mngt_cache_add_core_init_prefetch),
		OCF_PL_STEP(ocf_mngt_cache_add_core_detect_min_io_size),
		OCF_PL_STEP_TERMINATOR(),
	},
};

struct ocf_pipeline_properties ocf_mngt_cache_add_core_pipeline_props = {
	.priv_size = sizeof(struct ocf_cache_add_core_context),
	.finish = ocf_mngt_cache_add_core_finish,
	.steps = {
		OCF_PL_STEP(ocf_mngt_cache_add_core_prepare),
		OCF_PL_STEP(ocf_mngt_cache_add_core_insert),
		OCF_PL_STEP(ocf_mngt_cache_add_core_init_front_volume),
		OCF_PL_STEP(ocf_mngt_cache_add_core_init_prefetch),
		OCF_PL_STEP(ocf_mngt_cache_add_core_detect_min_io_size),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void _ocf_mngt_cache_add_core(ocf_cache_t cache,
		struct ocf_mngt_core_config *cfg,
		ocf_mngt_cache_add_core_end_t cmpl, void *priv)
{
	struct ocf_cache_add_core_context *context;
	ocf_pipeline_t pipeline;
	void *data;
	int result;

	OCF_CHECK_NULL(cache);

	result = ocf_pipeline_create(&pipeline, cache, cfg->try_add ?
			&ocf_mngt_cache_try_add_core_pipeline_props :
			&ocf_mngt_cache_add_core_pipeline_props);
	if (result)
		OCF_CMPL_RET(cache, NULL, priv, -OCF_ERR_NO_MEM);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->cfg = *cfg;

	data = env_vmalloc(cfg->uuid.size);
	if (!data) {
		result = -OCF_ERR_NO_MEM;
		goto err_pipeline;
	}

	result = env_memcpy(data, cfg->uuid.size, cfg->uuid.data,
			cfg->uuid.size);
	if (result)
		goto err_uuid;

	context->cfg.uuid.data = data;

	OCF_PL_NEXT_RET(pipeline);

err_uuid:
	env_vfree(data);
err_pipeline:
	ocf_pipeline_destroy(context->pipeline);
	OCF_CMPL_RET(cache, NULL, priv, result);
}

struct ocf_mngt_add_core_to_upper_cache_ctx {
	struct ocf_mngt_core_config core_cfg;
	ocf_cache_t cache;
	ocf_core_t core;
	ocf_core_t lower_core;
	ocf_mngt_cache_add_core_end_t cmpl;
	void *priv;
};

static void _ocf_mngt_cache_manage_upper_lock_cores_list_complete(void *priv)
{
	struct ocf_mngt_add_core_to_upper_cache_ctx *ctx = priv;
	ocf_cache_t main_cache;
	ocf_cache_t upper_cache = ctx->cache;
	ocf_mngt_cache_add_core_end_t cmpl = ctx->cmpl;
	ocf_core_t new_core = ctx->core;
	ocf_core_t lower_core = ctx->lower_core;
	void *inner_priv = ctx->priv;
	int res;

	main_cache = ocf_cache_ml_get_main_cache(ctx->cache);

	res = ocf_core_get_by_name(upper_cache, ctx->core_cfg.name,
			OCF_CORE_NAME_SIZE, &new_core);
	ENV_BUG_ON(res);

	env_mutex_lock(&main_cache->main.topology_lock);
	new_core->lower_core = lower_core;
	lower_core->upper_core = new_core;
	env_mutex_unlock(&main_cache->main.topology_lock);

	cmpl(ctx->cache, ctx->core, inner_priv, 0);
	env_free(ctx);
}

static void _ocf_mngt_cache_add_core_to_upper_cache_cb(ocf_cache_t cache,
		ocf_core_t core, void *priv, int err)
{
	struct ocf_mngt_add_core_to_upper_cache_ctx *ctx = priv;
	ocf_cache_t main_cache;

	if (err) {
		ocf_cache_log(cache, log_err,
				"Failed adding lower core %s to cache %s\n",
				ocf_core_get_name(ctx->lower_core),
				ocf_cache_get_name(cache));

		env_free(ctx);
		ctx->cmpl(cache, core, ctx->priv, err);
		return;
	}

	main_cache = ocf_cache_ml_get_main_cache(cache);

	core->minimal_io_size = ctx->lower_core->minimal_io_size;

	ctx->core = core;

	env_refcnt_freeze(&main_cache->main.fixed_topology);
	env_refcnt_register_zero_cb(&main_cache->main.fixed_topology,
			_ocf_mngt_cache_manage_upper_lock_cores_list_complete,
			ctx);
}

void ocf_mngt_cache_add_core_to_upper_cache(ocf_cache_t cache,
		ocf_core_t lower_core, ocf_mngt_cache_add_core_end_t cmpl,
		void *priv)
{
	struct ocf_mngt_add_core_to_upper_cache_ctx *ctx;
	struct ocf_core_volume_uuid core_uuid = {0};
	int ret;

	ret = ocf_core_get_front_uuid(lower_core, &core_uuid);
	if (ret)
		OCF_CMPL_RET(cache, NULL, priv, ret);

	ctx = env_malloc(sizeof(*ctx), ENV_MEM_NORMAL);
	if (!ctx)
		OCF_CMPL_RET(cache, NULL, priv, -OCF_ERR_NO_MEM);

	ocf_mngt_core_config_set_default(&ctx->core_cfg);
	env_strncpy(ctx->core_cfg.name, OCF_CORE_NAME_SIZE,
			ocf_core_get_name(lower_core), OCF_CORE_NAME_SIZE);
	ctx->core_cfg.uuid.data = &core_uuid;
	ctx->core_cfg.uuid.size = sizeof(core_uuid);
	ctx->core_cfg.volume_type = OCF_VOLUME_TYPE_CORE;

	ctx->cache = cache;
	ctx->lower_core = lower_core;
	ctx->cmpl = cmpl;
	ctx->priv = priv;
	_ocf_mngt_cache_add_core(cache, &ctx->core_cfg,
			_ocf_mngt_cache_add_core_to_upper_cache_cb, ctx);
}

struct _ocf_mngt_cache_add_core_ctx {
	ocf_cache_t cache;
	ocf_core_t last_successful_core;
	ocf_mngt_cache_add_core_end_t cmpl;
	void *priv;
	int err;
};

void _ocf_mngt_cache_remove_core(ocf_core_t core,
		ocf_mngt_cache_remove_core_end_t cmpl, void *priv);


static void _ocf_mngt_cache_add_lower_core_rollback_cb(void *priv, int err)
{
	struct _ocf_mngt_cache_add_core_ctx *ctx = priv;
	ocf_core_t rollback_core;

	if (err) {
		ocf_cache_log(ctx->cache, log_crit, "Couldn't roll back adding "
				"core.\n");
	} else if (ctx->last_successful_core) {
		rollback_core = ctx->last_successful_core;
		ctx->last_successful_core = rollback_core->lower_core;

		_ocf_mngt_cache_remove_core(rollback_core,
			      _ocf_mngt_cache_add_lower_core_rollback_cb, ctx);

		return;
	}

	ctx->cmpl(ctx->cache, NULL, ctx->priv, ctx->err);
	env_free(ctx);
}

static void _ocf_mngt_cache_add_core_next_cmpl(ocf_cache_t cache,
		ocf_core_t core, void *priv, int err)
{
	struct _ocf_mngt_cache_add_core_ctx *ctx = priv;
	ocf_core_t rollback_core;
	ocf_core_t lowest_core = NULL;

	if (err) {
		ctx->err = err;

		ocf_cache_log(cache, log_err, "Couldn't add core to cache %s.\n",
				ocf_cache_get_name(cache));

		if (ctx->last_successful_core) {
			rollback_core = ctx->last_successful_core;
			ctx->last_successful_core = rollback_core->lower_core;
			_ocf_mngt_cache_remove_core(rollback_core,
				      _ocf_mngt_cache_add_lower_core_rollback_cb, ctx);
			return;
		}

		goto out;
	}

	ctx->last_successful_core = core;

	if (ocf_cache_ml_is_lower(cache)) {
		ocf_mngt_cache_add_core_to_upper_cache(cache->upper_cache, core,
				_ocf_mngt_cache_add_core_next_cmpl, priv);

		return;
	}

	lowest_core = ocf_cache_ml_get_lowest_core(core);

out:
	ctx->cmpl(ctx->cache, lowest_core, ctx->priv, err);
	env_free(ctx);
}

void ocf_mngt_cache_add_core(ocf_cache_t cache,
               struct ocf_mngt_core_config *cfg,
               ocf_mngt_cache_add_core_end_t cmpl, void *priv)
{
	struct _ocf_mngt_cache_add_core_ctx *ctx;

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(cache, NULL, priv, -OCF_ERR_CACHE_STANDBY);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(cache, NULL, priv, -OCF_ERR_INVAL);

	if (!env_strnlen(cfg->name, OCF_CORE_NAME_SIZE))
		OCF_CMPL_RET(cache, NULL, priv, -OCF_ERR_INVAL);

	if (!ocf_cache_ml_is_main(cache))
		OCF_CMPL_RET(cache, NULL, priv, -OCF_ERR_CACHE_NOT_MAIN);

	if (ocf_cache_ml_is_lower(cache)) {
		ctx = env_zalloc(sizeof(*ctx), ENV_MEM_NORMAL);
		if (!ctx) {
			OCF_CMPL_RET(cache, NULL, priv, -OCF_ERR_NO_MEM);
		}
		ctx->cmpl = cmpl;
		ctx->priv = priv;

		_ocf_mngt_cache_add_core(cache, cfg,
				_ocf_mngt_cache_add_core_next_cmpl, ctx);
	} else {
		_ocf_mngt_cache_add_core(cache, cfg, cmpl, priv);
	}
}

struct ocf_mngt_cache_remove_core_context {
	ocf_mngt_cache_remove_core_end_t cmpl;
	void *priv;
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
	ocf_core_t core;
	const char *core_name;
	struct ocf_cleaner_wait_context cleaner_wait;
	ocf_core_t upper_core;
};

static void ocf_mngt_cache_remove_core_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_mngt_cache_remove_core_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (!error) {
		ocf_cache_log(cache, log_info, "Core %s successfully removed\n",
				context->core_name);
	} else {
		ocf_cache_log(cache, log_err, "Removing core %s failed\n",
				context->core_name);
	}

	ocf_cleaner_refcnt_unfreeze(cache);

	/* TODO: Remove cores top down */
	if (context->upper_core) {
		_ocf_mngt_cache_remove_core(context->upper_core,
			      context->cmpl, context->priv);
		ocf_pipeline_destroy(context->pipeline);
		return;
	}

	context->cmpl(context->priv, error);

	ocf_pipeline_destroy(context->pipeline);
}

static void ocf_mngt_cache_remove_core_flush_collision_complete(void *priv,
		int error)
{
	struct ocf_mngt_cache_remove_core_context *context = priv;

	error = error ? -OCF_ERR_CORE_NOT_REMOVED : 0;
	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static void _ocf_mngt_cache_remove_core_mapping(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_remove_core_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;

	if (!ocf_cache_is_device_attached(cache))
		OCF_PL_NEXT_RET(pipeline);

	cache_mngt_core_deinit_attached_meta(core);

	if (env_atomic_read(&core->runtime_meta->dirty_clines) == 0)
		OCF_PL_NEXT_RET(pipeline);

	ocf_metadata_flush_collision(cache,
			ocf_mngt_cache_remove_core_flush_collision_complete,
			context);
}

static void ocf_mngt_cache_remove_core_flush_superblock_complete(void *priv,
		int error)
{
	struct ocf_mngt_cache_remove_core_context *context = priv;

	error = error ? -OCF_ERR_WRITE_CACHE : 0;
	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static void _ocf_mngt_cache_remove_core_from_cache(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_remove_core_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;

	ocf_core_log(core, log_debug, "Removing core\n");

	if (ocf_cache_is_device_attached(cache))
		cache_mngt_core_remove_from_cleaning_pol(core);

	cache_mngt_core_remove_from_meta(core);
	cache_mngt_core_remove_from_cache(core);
	cache_mngt_core_deinit(core);

	if (!ocf_cache_is_device_attached(cache))
		OCF_PL_NEXT_RET(pipeline);

	ocf_metadata_flush_superblock(cache,
			ocf_mngt_cache_remove_core_flush_superblock_complete,
			context);
}

static void ocf_mngt_cache_remove_core_wait_cleaning_complete(void *priv)
{
	ocf_pipeline_t pipeline = priv;
	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_remove_core_wait_cleaning(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_remove_core_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (!ocf_cache_is_device_attached(cache))
		OCF_PL_NEXT_RET(pipeline);

	ocf_cleaner_refcnt_freeze(cache);
	ocf_cleaner_refcnt_register_zero_cb(cache, &context->cleaner_wait,
			ocf_mngt_cache_remove_core_wait_cleaning_complete,
			pipeline);
}

struct ocf_pipeline_properties ocf_mngt_cache_remove_core_pipeline_props = {
	.priv_size = sizeof(struct ocf_mngt_cache_remove_core_context),
	.finish = ocf_mngt_cache_remove_core_finish,
	.steps = {
		OCF_PL_STEP(ocf_mngt_cache_remove_core_wait_cleaning),
		OCF_PL_STEP(_ocf_mngt_cache_remove_core_mapping),
		OCF_PL_STEP(_ocf_mngt_cache_remove_core_from_cache),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void _ocf_mngt_cache_remove_core(ocf_core_t core,
		ocf_mngt_cache_remove_core_end_t cmpl, void *priv)
{
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
	int result;
	struct ocf_mngt_cache_remove_core_context *context;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_mngt_cache_remove_core_pipeline_props);
	if (result)
		OCF_CMPL_RET(priv, result);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->core = core;
	context->core_name = ocf_core_get_name(core);
	context->upper_core = core->upper_core;

	/*
	 * TODO: Make sure that the core doesn't have any in flight IOs before
	 * removing it. This currently can happen because of prefetcher or
	 * SWAP classifier.
	 */

	ocf_pipeline_next(pipeline);
}

void ocf_mngt_cache_remove_core(ocf_core_t core,
		ocf_mngt_cache_remove_core_end_t cmpl, void *priv)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(cache, -OCF_ERR_CACHE_STANDBY);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(cache, -OCF_ERR_INVAL);

	if (!ocf_cache_ml_is_main(cache)) {
		OCF_CMPL_RET(cache, -OCF_ERR_CACHE_NOT_MAIN);
	}

 	_ocf_mngt_cache_remove_core(core, cmpl, priv);
}

struct ocf_mngt_cache_detach_core_context {
	ocf_mngt_cache_detach_core_end_t cmpl;
	void *priv;
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
	ocf_core_t core;
	const char *core_name;
	struct ocf_cleaner_wait_context cleaner_wait;
};

static void _ocf_mngt_cache_detach_core(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_remove_core_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;

	ocf_core_log(core, log_debug, "Detaching core\n");

	if (!core->opened)
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_CORE_IN_INACTIVE_STATE);

	ocf_volume_deinit(&core->front_volume);
	ocf_volume_close(core->volume);
	core->opened = false;

	cache->ocf_core_inactive_count++;

	ocf_prefetch_destroy(core);
	
#ifdef OCF_DEBUG_STATS
	/* if cache-volume is composite, reset core stats in cache */
	ocf_composite_volume_stats_initialize(cache, core,
		OCF_COMPOSITE_VOLUME_MEMBER_ID_INVALID);
#endif
	env_bit_set(ocf_cache_state_incomplete,
			&cache->cache_state);
	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_detach_core_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_mngt_cache_remove_core_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (!error) {
		ocf_cache_log(cache, log_info, "Core %s successfully detached\n",
				context->core_name);
	} else {
		ocf_cache_log(cache, log_err, "Detaching core %s failed\n",
				context->core_name);
	}

	ocf_cleaner_refcnt_unfreeze(context->cache);

	context->cmpl(context->priv, error);

	ocf_pipeline_destroy(context->pipeline);
}

static void ocf_mngt_cache_detach_core_wait_cleaning_complete(void *priv)
{
	ocf_pipeline_t pipeline = priv;
	ocf_pipeline_next(pipeline);
}

static void ocf_mngt_cache_detach_core_wait_cleaning(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_remove_core_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (!ocf_cache_is_device_attached(cache))
		OCF_PL_NEXT_RET(pipeline);

	ocf_cleaner_refcnt_freeze(cache);
	ocf_cleaner_refcnt_register_zero_cb(cache, &context->cleaner_wait,
			ocf_mngt_cache_detach_core_wait_cleaning_complete,
			pipeline);
}

struct ocf_pipeline_properties ocf_mngt_cache_detach_core_pipeline_props = {
	.priv_size = sizeof(struct ocf_mngt_cache_detach_core_context),
	.finish = ocf_mngt_cache_detach_core_finish,
	.steps = {
		OCF_PL_STEP(ocf_mngt_cache_detach_core_wait_cleaning),
		OCF_PL_STEP(_ocf_mngt_cache_detach_core),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_cache_detach_core(ocf_core_t core,
		ocf_mngt_cache_detach_core_end_t cmpl, void *priv)
{
	struct ocf_mngt_cache_detach_core_context *context;
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
	int result;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);

	if (!ocf_cache_ml_is_main(cache))
		OCF_CMPL_RET(priv, -OCF_ERR_CACHE_NOT_MAIN);

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(cache, -OCF_ERR_CACHE_STANDBY);

	if (!cache->mngt_queue)
		OCF_CMPL_RET(cache, -OCF_ERR_INVAL);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_mngt_cache_detach_core_pipeline_props);
	if (result)
		OCF_CMPL_RET(priv, result);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->core = core;
	context->core_name = ocf_core_get_name(core);

	ocf_pipeline_next(pipeline);
}

int ocf_mngt_core_set_uuid(ocf_core_t core, const struct ocf_volume_uuid *uuid)
{
	struct ocf_volume_uuid *current_uuid;
	int result;
	int diff;
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(uuid);
	OCF_CHECK_NULL(uuid->data);

	cache = ocf_core_get_cache(core);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	current_uuid = &ocf_core_get_volume(core)->uuid;

	result = env_memcmp(current_uuid->data, current_uuid->size,
			uuid->data, uuid->size, &diff);
	if (result)
		return result;

	if (!diff) {
		/* UUIDs are identical */
		return 0;
	}

	result = ocf_mngt_core_set_uuid_metadata(core, uuid, NULL);
	if (result)
		return result;

	ocf_volume_set_uuid(core->volume, uuid);

	return result;
}

int ocf_mngt_core_set_user_metadata(ocf_core_t core, void *data, size_t size)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(data);

	cache = ocf_core_get_cache(core);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (size > OCF_CORE_USER_DATA_SIZE)
		return -EINVAL;

	return env_memcpy(core->conf_meta->user_data,
			OCF_CORE_USER_DATA_SIZE, data, size);
}

int ocf_mngt_core_get_user_metadata(ocf_core_t core, void *data, size_t size)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(data);

	cache = ocf_core_get_cache(core);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (size > sizeof(core->conf_meta->user_data))
		return -EINVAL;

	return env_memcpy(data, size, core->conf_meta->user_data,
			OCF_CORE_USER_DATA_SIZE);
}

static int _cache_mngt_set_core_seq_cutoff_threshold(ocf_core_t core, void *cntx)
{
	uint32_t threshold = *(uint32_t*) cntx;
	uint32_t threshold_old = ocf_core_get_seq_cutoff_threshold(core);

	if (threshold < OCF_SEQ_CUTOFF_MIN_THRESHOLD ||
			threshold > OCF_SEQ_CUTOFF_MAX_THRESHOLD) {
		ocf_core_log(core, log_info,
				"Invalid sequential cutoff threshold!\n");
		return -OCF_ERR_INVAL;
	}

	if (threshold_old == threshold) {
		ocf_core_log(core, log_info,
				"Sequential cutoff threshold %u bytes is "
				"already set\n", threshold);
		return 0;
	}

	env_atomic_set(&core->conf_meta->seq_cutoff_threshold, threshold);

	ocf_core_log(core, log_info, "Changing sequential cutoff "
			"threshold from %u to %u bytes successful\n",
			threshold_old, threshold);

	return 0;
}

int ocf_mngt_core_set_seq_cutoff_threshold(ocf_core_t core, uint32_t thresh)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);
	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		return -OCF_ERR_CACHE_DETACHED;

	return _cache_mngt_set_core_seq_cutoff_threshold(core, &thresh);
}

int ocf_mngt_core_set_seq_cutoff_threshold_all(ocf_cache_t cache,
		uint32_t thresh)
{
	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		return -OCF_ERR_CACHE_DETACHED;

	return ocf_core_visit(cache, _cache_mngt_set_core_seq_cutoff_threshold,
			&thresh, true);
}

int ocf_mngt_core_get_seq_cutoff_threshold(ocf_core_t core, uint32_t *thresh)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(thresh);

	cache = ocf_core_get_cache(core);
	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	*thresh = ocf_core_get_seq_cutoff_threshold(core);

	return 0;
}

static const char *_ocf_seq_cutoff_policy_names[ocf_seq_cutoff_policy_max] = {
	[ocf_seq_cutoff_policy_always] = "always",
	[ocf_seq_cutoff_policy_full] = "full",
	[ocf_seq_cutoff_policy_never] = "never",
};

static const char *_cache_mngt_seq_cutoff_policy_get_name(
		ocf_seq_cutoff_policy policy)
{
	if (policy < 0 || policy >= ocf_seq_cutoff_policy_max)
		return NULL;

	return _ocf_seq_cutoff_policy_names[policy];
}

static int _cache_mngt_set_core_seq_cutoff_policy(ocf_core_t core, void *cntx)
{
	ocf_seq_cutoff_policy policy = *(ocf_seq_cutoff_policy*) cntx;
	uint32_t policy_old = ocf_core_get_seq_cutoff_policy(core);

	if (policy_old == policy) {
		ocf_core_log(core, log_info,
				"Sequential cutoff policy %s is already set\n",
				_cache_mngt_seq_cutoff_policy_get_name(policy));
		return 0;
	}

	if (policy < 0 || policy >= ocf_seq_cutoff_policy_max) {
		ocf_core_log(core, log_info,
				"Wrong sequential cutoff policy!\n");
		return -OCF_ERR_INVAL;
	}

	if (ocf_core_get_cache(core)->ocf_classifier & OCF_CLASSIFIER_IGNORE_OCF) {
		ocf_core_log(core, log_crit,
				"Sequential cutoff policy locked to %s. Request ignored.\n",
				_cache_mngt_seq_cutoff_policy_get_name(policy_old));
		return 0;
	}

	env_atomic_set(&core->conf_meta->seq_cutoff_policy, policy);

	ocf_core_log(core, log_info,
			"Changing sequential cutoff policy from %s to %s\n",
			_cache_mngt_seq_cutoff_policy_get_name(policy_old),
			_cache_mngt_seq_cutoff_policy_get_name(policy));

	return 0;
}

int ocf_mngt_core_set_seq_cutoff_policy(ocf_core_t core,
		ocf_seq_cutoff_policy policy)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);
	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		return -OCF_ERR_CACHE_DETACHED;

	return _cache_mngt_set_core_seq_cutoff_policy(core, &policy);
}
int ocf_mngt_core_set_seq_cutoff_policy_all(ocf_cache_t cache,
		ocf_seq_cutoff_policy policy)
{
	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		return -OCF_ERR_CACHE_DETACHED;

	return ocf_core_visit(cache, _cache_mngt_set_core_seq_cutoff_policy,
						  &policy, true);
}

int ocf_mngt_core_get_seq_cutoff_policy(ocf_core_t core,
		ocf_seq_cutoff_policy *policy)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(policy);

	cache = ocf_core_get_cache(core);
	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	*policy = ocf_core_get_seq_cutoff_policy(core);

	return 0;
}

static int _cache_mngt_set_core_seq_cutoff_promo_count(ocf_core_t core,
		void *cntx)
{
	uint32_t count = *(uint32_t*) cntx;
	uint32_t count_old = ocf_core_get_seq_cutoff_promotion_count(core);

	if (count < OCF_SEQ_CUTOFF_MIN_PROMOTION_COUNT ||
			count > OCF_SEQ_CUTOFF_MAX_PROMOTION_COUNT) {
		ocf_core_log(core, log_info,
				"Invalid sequential cutoff promotion count!\n");
		return -OCF_ERR_INVAL;
	}


	if (count_old == count) {
		ocf_core_log(core, log_info,
				"Sequential cutoff promotion count %u "
				"is already set\n", count);
		return 0;
	}

	env_atomic_set(&core->conf_meta->seq_cutoff_promo_count, count);

	ocf_core_log(core, log_info, "Changing sequential cutoff promotion "
			"count from %u to %u successful\n",
			count_old, count);

	return 0;
}

int ocf_mngt_core_set_seq_cutoff_promotion_count(ocf_core_t core,
		uint32_t count)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);
	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		return -OCF_ERR_CACHE_DETACHED;

	return _cache_mngt_set_core_seq_cutoff_promo_count(core, &count);
}

int ocf_mngt_core_set_seq_cutoff_promotion_count_all(ocf_cache_t cache,
		uint32_t count)
{
	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		return -OCF_ERR_CACHE_DETACHED;

	return ocf_core_visit(cache, _cache_mngt_set_core_seq_cutoff_promo_count,
						  &count, true);
}

int ocf_mngt_core_get_seq_cutoff_promotion_count(ocf_core_t core,
		uint32_t *count)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(count);

	cache = ocf_core_get_cache(core);
	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	*count = ocf_core_get_seq_cutoff_promotion_count(core);

	return 0;
}

static int _cache_mngt_set_core_seq_cutoff_promote_on_threshold(
		ocf_core_t core, void *cntx)
{
	bool promote = *(bool*) cntx;
	bool promote_old = ocf_core_get_seq_cutoff_promote_on_threshold(core);

	if (promote_old == promote) {
		ocf_core_log(core, log_info,
				"Sequential cutoff promote on threshold "
				"is already set to %s\n", promote ? "true" : "false");
		return 0;
	}

	env_atomic_set(&core->conf_meta->seq_cutoff_promote_on_threshold,
			promote);

	ocf_core_log(core, log_info, "Changing sequential cutoff promote "
			"on threshold from %s to %s successful\n",
			promote_old ? "true" : "false", promote ? "true" : "false");

	return 0;
}

int ocf_mngt_core_set_seq_cutoff_promote_on_threshold(ocf_core_t core,
		bool promote)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);
	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	return _cache_mngt_set_core_seq_cutoff_promote_on_threshold(core, &promote);
}

int ocf_mngt_core_set_seq_cutoff_promote_on_threshold_all(ocf_cache_t cache,
		bool promote)
{
	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	return ocf_core_visit(cache,
			_cache_mngt_set_core_seq_cutoff_promote_on_threshold,
			&promote, true);
}

int ocf_mngt_core_get_seq_cutoff_promote_on_threshold(ocf_core_t core,
		bool *promote)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(promote);

	cache = ocf_core_get_cache(core);
	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	*promote = ocf_core_get_seq_cutoff_promote_on_threshold(core);

	return 0;
}
