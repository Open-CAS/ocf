/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_mngt_common.h"
#include "ocf_mngt_core_priv.h"
#include "../ocf_priv.h"
#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../utils/utils_device.h"
#include "../utils/utils_pipeline.h"
#include "../ocf_stats_priv.h"
#include "../ocf_def_priv.h"

static ocf_seq_no_t _ocf_mngt_get_core_seq_no(ocf_cache_t cache)
{
	if (cache->conf_meta->curr_core_seq_no == OCF_SEQ_NO_MAX)
		return OCF_SEQ_NO_INVALID;

	return ++cache->conf_meta->curr_core_seq_no;
}

static int _ocf_mngt_cache_try_add_core(ocf_cache_t cache, ocf_core_t *core,
		struct ocf_mngt_core_config *cfg)
{
	int result = 0;
	ocf_core_t tmp_core;
	ocf_volume_t volume;

	tmp_core = &cache->core[cfg->core_id];
	volume = &tmp_core->volume;

	if (ocf_ctx_get_volume_type_id(cache->owner, volume->type) !=
			cfg->volume_type) {
		result = -OCF_ERR_INVAL_VOLUME_TYPE;
		goto error_out;
	}

	result = ocf_volume_open(volume, NULL);
	if (result)
		goto error_out;

	if (!ocf_volume_get_length(volume)) {
		result = -OCF_ERR_CORE_NOT_AVAIL;
		goto error_after_open;
	}

	tmp_core->opened = true;

	if (!(--cache->ocf_core_inactive_count))
		env_bit_clear(ocf_cache_state_incomplete, &cache->cache_state);

	*core = tmp_core;
	return 0;

error_after_open:
	ocf_volume_close(volume);
error_out:
	*core = NULL;
	return result;
}

struct ocf_cache_add_core_context {
	ocf_mngt_cache_add_core_end_t cmpl;
	void *priv;
	ocf_pipeline_t pipeline;
	struct ocf_mngt_core_config cfg;
	char core_name[OCF_CORE_NAME_SIZE];
	ocf_cache_t cache;
	ocf_core_t core;

	struct {
		bool uuid_set : 1;
		bool volume_inited : 1;
		bool volume_opened : 1;
		bool clean_pol_added : 1;
		bool counters_allocated : 1;
	} flags;
};

static void _ocf_mngt_cache_add_core_handle_error(
		struct ocf_cache_add_core_context *context)
{
	struct ocf_mngt_core_config *cfg = &context->cfg;
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;
	ocf_volume_t volume;
	ocf_cleaning_t clean_type;

	if (!core)
		return;

	volume = &core->volume;
	clean_type = cache->conf_meta->cleaning_policy_type;

	if (context->flags.counters_allocated) {
		env_bit_clear(cfg->core_id,
				cache->conf_meta->valid_core_bitmap);
		cache->core_conf_meta[cfg->core_id].added = false;
		core->opened = false;

		env_free(core->counters);
		core->counters = NULL;
	}

	if (context->flags.clean_pol_added) {
		if (cleaning_policy_ops[clean_type].remove_core)
			cleaning_policy_ops[clean_type].remove_core(cache,
					cfg->core_id);
	}

	if (context->flags.volume_opened)
		ocf_volume_close(volume);

	if (context->flags.volume_inited)
		ocf_volume_deinit(volume);

	if (context->flags.uuid_set)
		ocf_metadata_clear_core_uuid(core);
}

static void _ocf_mngt_cache_add_core_flush_sb_complete(void *priv, int error)
{
	struct ocf_cache_add_core_context *context = priv;

	if (error) {
		ocf_pipeline_finish(context->pipeline, -OCF_ERR_WRITE_CACHE);
		return;
	}

	/* Increase value of added cores */
	context->cache->conf_meta->core_count++;

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_cache_add_core(ocf_cache_t cache,
		struct ocf_cache_add_core_context *context)
{
	struct ocf_mngt_core_config *cfg = &context->cfg;
	ocf_core_t core;
	struct ocf_volume_uuid new_uuid;
	ocf_volume_t volume;
	ocf_volume_type_t type;
	ocf_seq_no_t core_sequence_no;
	ocf_cleaning_t clean_type;
	uint64_t length;
	int result = 0;

	core = &cache->core[cfg->core_id];
	context->core = core;

	volume = &core->volume;
	volume->cache = cache;

	/* Set uuid */
	result = ocf_metadata_set_core_uuid(core, &cfg->uuid, &new_uuid);
	if (result) {
		ocf_pipeline_finish(context->pipeline, result);
		return;
	}
	context->flags.uuid_set = true;

	type = ocf_ctx_get_volume_type(cache->owner, cfg->volume_type);
	if (!type) {
		ocf_pipeline_finish(context->pipeline,
				-OCF_ERR_INVAL_VOLUME_TYPE);
		return;
	}

	result = ocf_volume_init(volume, type, &new_uuid, false);
	if (result) {
		ocf_pipeline_finish(context->pipeline, result);
		return;
	}
	context->flags.volume_inited = true;

	if (cfg->user_metadata.data && cfg->user_metadata.size > 0) {
		result = ocf_mngt_core_set_user_metadata(core,
				cfg->user_metadata.data,
				cfg->user_metadata.size);
		if (result) {
			ocf_pipeline_finish(context->pipeline, result);
			return;
		}
	}

	result = ocf_volume_open(volume, NULL);
	if (result) {
		ocf_pipeline_finish(context->pipeline, result);
		return;
	}
	context->flags.volume_opened = true;

	length = ocf_volume_get_length(volume);
	if (!length) {
		ocf_pipeline_finish(context->pipeline, -OCF_ERR_CORE_NOT_AVAIL);
		return;
	}
	cache->core_conf_meta[cfg->core_id].length = length;

	clean_type = cache->conf_meta->cleaning_policy_type;
	if (ocf_cache_is_device_attached(cache) &&
			cleaning_policy_ops[clean_type].add_core) {
		result = cleaning_policy_ops[clean_type].add_core(cache,
				cfg->core_id);
		if (result) {
			ocf_pipeline_finish(context->pipeline, result);
			return;
		}
		context->flags.clean_pol_added = true;
	}

	/* When adding new core to cache, allocate stat counters */
	core->counters =
		env_zalloc(sizeof(*core->counters), ENV_MEM_NORMAL);
	if (!core->counters) {
		ocf_pipeline_finish(context->pipeline, -OCF_ERR_NO_MEM);
		return;
	}
	context->flags.counters_allocated = true;

	/* When adding new core to cache, reset all core/cache statistics */
	ocf_core_stats_initialize(core);
	env_atomic_set(&cache->core_runtime_meta[cfg->core_id].
			cached_clines, 0);
	env_atomic_set(&cache->core_runtime_meta[cfg->core_id].
			dirty_clines, 0);
	env_atomic64_set(&cache->core_runtime_meta[cfg->core_id].
			dirty_since, 0);

	/* In metadata mark data this core was added into cache */
	env_bit_set(cfg->core_id, cache->conf_meta->valid_core_bitmap);
	cache->core_conf_meta[cfg->core_id].added = true;
	core->opened = true;

	/* Set default cache parameters for sequential */
	cache->core_conf_meta[cfg->core_id].seq_cutoff_policy =
		ocf_seq_cutoff_policy_default;
	cache->core_conf_meta[cfg->core_id].seq_cutoff_threshold =
		cfg->seq_cutoff_threshold;

	/* Add core sequence number for atomic metadata matching */
	core_sequence_no = _ocf_mngt_get_core_seq_no(cache);
	if (core_sequence_no == OCF_SEQ_NO_INVALID) {
		ocf_pipeline_finish(context->pipeline, -OCF_ERR_TOO_MANY_CORES);
		return;
	}
	cache->core_conf_meta[cfg->core_id].seq_no = core_sequence_no;

	/* Update super-block with core device addition */
	ocf_metadata_flush_superblock(cache,
			_ocf_mngt_cache_add_core_flush_sb_complete, context);
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

static int __ocf_mngt_lookup_core_uuid(ocf_cache_t cache,
		struct ocf_mngt_core_config *cfg)
{
	int i;

	for (i = 0; i < OCF_CORE_MAX; i++) {
		ocf_core_t core = &cache->core[i];

		if (!env_bit_test(i, cache->conf_meta->valid_core_bitmap))
			continue;

		if (cache->core[i].opened)
			continue;

		if (ocf_ctx_get_volume_type_id(cache->owner, core->volume.type)
				!= cfg->volume_type) {
			continue;
		}

		if (!env_strncmp(core->volume.uuid.data, cfg->uuid.data,
					OCF_MIN(core->volume.uuid.size,
						cfg->uuid.size)))
			return i;
	}

	return OCF_CORE_MAX;
}

static int __ocf_mngt_try_find_core_id(ocf_cache_t cache,
		struct ocf_mngt_core_config *cfg, ocf_core_id_t tmp_core_id)
{
	if (tmp_core_id == OCF_CORE_MAX) {
		/* FIXME: uuid.data could be not NULL-terminated ANSI string */
		ocf_cache_log(cache, log_err, "Core with uuid %s not found in "
				"cache metadata\n", (char*) cfg->uuid.data);
		return -OCF_ERR_CORE_NOT_AVAIL;
	}

	if (cfg->core_id != tmp_core_id) {
		ocf_cache_log(cache, log_err,
				"Given core id doesn't match with metadata\n");
		return -OCF_ERR_CORE_NOT_AVAIL;
	}


	cfg->core_id = tmp_core_id;
	return 0;
}

static int __ocf_mngt_find_core_id(ocf_cache_t cache,
		struct ocf_mngt_core_config *cfg, ocf_core_id_t tmp_core_id)
{
	if (tmp_core_id != OCF_CORE_MAX) {
		ocf_cache_log(cache, log_err,
				"Core ID already added as inactive with id:"
				" %hu.\n", tmp_core_id);
		return -OCF_ERR_CORE_NOT_AVAIL;
	}

	if (cfg->core_id == OCF_CORE_MAX) {
		ocf_cache_log(cache, log_debug, "Core ID is unspecified - "
				"will set first available number\n");

		/* Core is unspecified */
		cfg->core_id = _ocf_mngt_find_first_free_core(
				cache->conf_meta->valid_core_bitmap);
		/* no need to check if find_first_zero_bit failed and
		 * *core_id == MAX_CORE_OBJS_PER_CACHE, as above there is check
		 * for core_count being greater or equal to
		 * MAX_CORE_OBJS_PER_CACHE
		 */
	} else if (cfg->core_id < OCF_CORE_MAX) {
		/* check if id is not used already */
		if (env_bit_test(cfg->core_id,
					cache->conf_meta->valid_core_bitmap)) {
			ocf_cache_log(cache, log_debug,
					"Core ID already allocated: %d.\n",
					cfg->core_id);
			return -OCF_ERR_CORE_NOT_AVAIL;
		}
	} else {
		ocf_cache_log(cache, log_err,
				"Core ID exceeds maximum of %d.\n",
				OCF_CORE_MAX);
		return -OCF_ERR_CORE_NOT_AVAIL;
	}

	return 0;
}

static int _ocf_mngt_find_core_id(ocf_cache_t cache,
		struct ocf_mngt_core_config *cfg)
{
	int result;
	ocf_core_id_t tmp_core_id;

	if (cache->conf_meta->core_count >= OCF_CORE_MAX)
		return -OCF_ERR_TOO_MANY_CORES;

	tmp_core_id = __ocf_mngt_lookup_core_uuid(cache, cfg);

	if (cfg->try_add)
		result = __ocf_mngt_try_find_core_id(cache, cfg, tmp_core_id);
	else
		result = __ocf_mngt_find_core_id(cache, cfg, tmp_core_id);

	return result;
}

int ocf_mngt_core_init_front_volume(ocf_core_t core)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_volume_type_t type;
	struct ocf_volume_uuid uuid = {
		.data = core,
		.size = sizeof(core),
	};
	int ret;

	type = ocf_ctx_get_volume_type(cache->owner, 0);
	if (!type)
		return -OCF_ERR_INVAL;

	ret = ocf_volume_init(&core->front_volume, type, &uuid, false);
	if (ret)
		return ret;

	return ocf_volume_open(&core->front_volume, NULL);
}

static void ocf_mngt_cache_add_core_prepare(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_add_core_context *context = priv;
	ocf_cache_t cache = context->cache;
	char *core_name = context->core_name;
	int result;

	result = _ocf_mngt_find_core_id(cache, &context->cfg);
	if (result) {
		ocf_pipeline_finish(context->pipeline, result);
		return;
	}

	if (context->cfg.name) {
		result = env_strncpy(core_name, sizeof(context->core_name),
				context->cfg.name, sizeof(context->core_name));
		if (result) {
			ocf_pipeline_finish(context->pipeline, result);
			return;
		}
	} else {
		result = snprintf(core_name, sizeof(context->core_name),
				"core%hu", context->cfg.core_id);
		if (result < 0) {
			ocf_pipeline_finish(context->pipeline, result);
			return;
		}
	}

	result = ocf_core_set_name(&cache->core[context->cfg.core_id],
			core_name, sizeof(context->core_name));
	if (result) {
		ocf_pipeline_finish(context->pipeline, result);
		return;
	}

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_add_core_insert(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_add_core_context *context = priv;
	ocf_cache_t cache = context->cache;
	char *core_name = context->core_name;
	int result;

	ocf_cache_log(cache, log_debug, "Inserting core %s\n", core_name);

	if (context->cfg.try_add) {
		result = _ocf_mngt_cache_try_add_core(cache, &context->core,
				&context->cfg);
		if (result) {
			ocf_pipeline_finish(context->pipeline, result);
			return;
		}

		ocf_pipeline_next(context->pipeline);
		return;
	}

	_ocf_mngt_cache_add_core(cache, context);
}

static void ocf_mngt_cache_add_core_init_front_volume(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_cache_add_core_context *context = priv;
	int result;

	result = ocf_mngt_core_init_front_volume(context->core);
	if (result) {
		ocf_pipeline_finish(context->pipeline, result);
		return;
	}

	ocf_pipeline_next(context->pipeline);
}

static void ocf_mngt_cache_add_core_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_cache_add_core_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;

	if (error) {
		_ocf_mngt_cache_add_core_handle_error(context);

		if (error == -OCF_ERR_CORE_NOT_AVAIL) {
			ocf_cache_log(cache, log_err, "Core %s is zero size\n",
					context->core_name);
		}
		ocf_cache_log(cache, log_err, "Adding core %s failed\n",
				context->core_name);
		goto out;
	}

	ocf_core_log(core, log_info, "Successfully added\n");

out:
	context->cmpl(cache, core, context->priv, error);
	env_vfree(context->cfg.uuid.data);
	ocf_pipeline_destroy(context->pipeline);
}

struct ocf_pipeline_properties ocf_mngt_cache_add_core_pipeline_properties = {
	.priv_size = sizeof(struct ocf_cache_add_core_context),
	.finish = ocf_mngt_cache_add_core_finish,
	.steps = {
		OCF_PL_STEP(ocf_mngt_cache_add_core_prepare),
		OCF_PL_STEP(ocf_mngt_cache_add_core_insert),
		OCF_PL_STEP(ocf_mngt_cache_add_core_init_front_volume),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_cache_add_core(ocf_cache_t cache,
		struct ocf_mngt_core_config *cfg,
		ocf_mngt_cache_add_core_end_t cmpl, void *priv)
{
	struct ocf_cache_add_core_context *context;
	ocf_pipeline_t pipeline;
	void *data;
	int result;

	OCF_CHECK_NULL(cache);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_mngt_cache_add_core_pipeline_properties);
	if (result) {
		cmpl(cache, NULL, priv, -OCF_ERR_NO_MEM);
		return;
	}

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


	ocf_pipeline_next(pipeline);
	return;

err_uuid:
	env_vfree(data);
err_pipeline:
	ocf_pipeline_destroy(context->pipeline);
	cmpl(cache, NULL, priv, result);
}

/*
 * Synchronously wait until cleaning triggered by eviction finishes.
 * TODO: Replace it with asynchronous mechanism.
 */
static int _ocf_cleaning_wait_for_finish(ocf_cache_t cache, int32_t timeout_ms)
{
	if (!ocf_cache_is_device_attached(cache))
		return 0;

	while (ocf_cache_has_pending_cleaning(cache)) {
		env_msleep(20);

		timeout_ms -= 20;
		if (timeout_ms <= 0)
			return -EBUSY;
	}

	return 0;
}

struct ocf_mngt_cache_remove_core_context {
	ocf_mngt_cache_remove_core_end_t cmpl;
	void *priv;
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
	const char *core_name;
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

	context->cmpl(context->priv, error);

	ocf_pipeline_destroy(context->pipeline);
}

struct ocf_pipeline_properties ocf_mngt_cache_remove_core_pipeline_props = {
	.priv_size = sizeof(struct ocf_mngt_cache_remove_core_context),
	.finish = ocf_mngt_cache_remove_core_finish,
	.steps = {
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void ocf_mngt_cache_remove_core_flush_sb_complete(void *priv, int error)
{
	struct ocf_mngt_cache_remove_core_context *context = priv;

	if (error) {
		ocf_pipeline_finish(context->pipeline,
				-OCF_ERR_WRITE_CACHE);
		return;
	}

	ocf_pipeline_next(context->pipeline);
}

void ocf_mngt_cache_remove_core(ocf_core_t core,
		ocf_mngt_cache_remove_core_end_t cmpl, void *priv)
{
	struct ocf_mngt_cache_remove_core_context *context;
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
	ocf_core_id_t core_id;
	int result;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);
	core_id = ocf_core_get_id(core);

	/* TODO: Make this asynchronous */
	if (_ocf_cleaning_wait_for_finish(cache, 60 * 1000)) {
		cmpl(priv, -OCF_ERR_CACHE_IN_USE);
		return;
	}

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_mngt_cache_remove_core_pipeline_props);
	if (result) {
		cmpl(priv, result);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;
	context->core_name = ocf_core_get_name(core);

	ocf_core_log(core, log_debug, "Removing core\n");

	ocf_volume_close(&core->front_volume);

	/* Deinit everything*/
	if (ocf_cache_is_device_attached(cache)) {
		cache_mng_core_deinit_attached_meta(cache, core_id);
		cache_mng_core_remove_from_cleaning_pol(cache, core_id);
	}
	cache_mng_core_remove_from_meta(cache, core_id);
	cache_mng_core_remove_from_cache(cache, core_id);
	cache_mng_core_close(cache, core_id);

	/* Update super-block with core device removal */
	ocf_metadata_flush_superblock(cache,
			ocf_mngt_cache_remove_core_flush_sb_complete, context);
}

static int _ocf_mngt_cache_detach_core(ocf_core_t core)
{
	struct ocf_cache *cache = core->volume.cache;
	ocf_core_id_t core_id = ocf_core_get_id(core);
	int status;

	status = cache_mng_core_close(cache, core_id);
	if (!status) {
		cache->ocf_core_inactive_count++;
		env_bit_set(ocf_cache_state_incomplete,
				&cache->cache_state);
	}

	return status;
}

void ocf_mngt_cache_detach_core(ocf_core_t core,
		ocf_mngt_cache_detach_core_end_t cmpl, void *priv)
{
	ocf_cache_t cache;
	const char *core_name;
	int result;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);
	core_name = ocf_core_get_name(core);

	/* TODO: Make this asynchronous */
	if (_ocf_cleaning_wait_for_finish(cache, 60 * 1000)) {
		cmpl(priv, -OCF_ERR_CACHE_IN_USE);
		return;
	}

	ocf_core_log(core, log_debug, "Detaching core\n");

	result = _ocf_mngt_cache_detach_core(core);
	if (!result) {
		ocf_cache_log(cache, log_info, "Core %s successfully detached\n",
				core_name);
	} else {
		ocf_cache_log(cache, log_err, "Detaching core %s failed\n",
				core_name);
	}

	cmpl(priv, result);
}

int ocf_mngt_core_set_uuid(ocf_core_t core, const struct ocf_volume_uuid *uuid)
{
	struct ocf_volume_uuid *current_uuid;
	int result;
	int diff;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(uuid);
	OCF_CHECK_NULL(uuid->data);

	current_uuid = &ocf_core_get_volume(core)->uuid;

	result = env_memcmp(current_uuid->data, current_uuid->size,
			uuid->data, uuid->size, &diff);
	if (result)
		return result;

	if (!diff) {
		/* UUIDs are identical */
		return 0;
	}

	result = ocf_metadata_set_core_uuid(core, uuid, NULL);
	if (result)
		return result;

	ocf_volume_set_uuid(&core->volume, uuid);

	return result;
}

int ocf_mngt_core_set_user_metadata(ocf_core_t core, void *data, size_t size)
{
	ocf_cache_t cache;
	uint32_t core_id;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(data);

	cache = ocf_core_get_cache(core);
	core_id = ocf_core_get_id(core);

	if (size > OCF_CORE_USER_DATA_SIZE)
		return -EINVAL;

	env_memcpy(cache->core_conf_meta[core_id].user_data,
			OCF_CORE_USER_DATA_SIZE, data, size);

	return 0;
}

int ocf_mngt_core_get_user_metadata(ocf_core_t core, void *data, size_t size)
{
	uint32_t core_id;
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);

	core_id = ocf_core_get_id(core);
	cache = ocf_core_get_cache(core);

	if (size > sizeof(cache->core_conf_meta[core_id].user_data))
		return -EINVAL;

	env_memcpy(data, size, cache->core_conf_meta[core_id].user_data,
			OCF_CORE_USER_DATA_SIZE);

	return 0;
}

static int _cache_mng_set_core_seq_cutoff_threshold(ocf_core_t core, void *cntx)
{
	uint32_t threshold = *(uint32_t*) cntx;
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_core_id_t core_id = ocf_core_get_id(core);
	uint32_t threshold_old = cache->core_conf_meta[core_id].
		seq_cutoff_threshold;

	if (threshold_old == threshold) {
		ocf_core_log(core, log_info,
				"Sequential cutoff threshold %u bytes is "
				"already set\n", threshold);
		return 0;
	}
	cache->core_conf_meta[core_id].seq_cutoff_threshold = threshold;

	ocf_core_log(core, log_info, "Changing sequential cutoff "
			"threshold from %u to %u bytes successful\n",
			threshold_old, threshold);

	return 0;
}

int ocf_mngt_core_set_seq_cutoff_threshold(ocf_core_t core, uint32_t thresh)
{
	OCF_CHECK_NULL(core);

	return _cache_mng_set_core_seq_cutoff_threshold(core, &thresh);
}

int ocf_mngt_core_set_seq_cutoff_threshold_all(ocf_cache_t cache,
		uint32_t thresh)
{
	OCF_CHECK_NULL(cache);

	return ocf_core_visit(cache, _cache_mng_set_core_seq_cutoff_threshold,
			&thresh, true);
}

int ocf_mngt_core_get_seq_cutoff_threshold(ocf_core_t core, uint32_t *thresh)
{
	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(thresh);

	*thresh = ocf_core_get_seq_cutoff_threshold(core);

	return 0;
}

static const char *_ocf_seq_cutoff_policy_names[ocf_seq_cutoff_policy_max] = {
	[ocf_seq_cutoff_policy_always] = "always",
	[ocf_seq_cutoff_policy_full] = "full",
	[ocf_seq_cutoff_policy_never] = "never",
};

static const char *_cache_mng_seq_cutoff_policy_get_name(
		ocf_seq_cutoff_policy policy)
{
	if (policy < 0 || policy >= ocf_seq_cutoff_policy_max)
		return NULL;

	return _ocf_seq_cutoff_policy_names[policy];
}

static int _cache_mng_set_core_seq_cutoff_policy(ocf_core_t core, void *cntx)
{
	ocf_seq_cutoff_policy policy = *(ocf_seq_cutoff_policy*) cntx;
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_core_id_t core_id = ocf_core_get_id(core);
	uint32_t policy_old = cache->core_conf_meta[core_id].seq_cutoff_policy;

	if (policy_old == policy) {
		ocf_core_log(core, log_info,
				"Sequential cutoff policy %s is already set\n",
				_cache_mng_seq_cutoff_policy_get_name(policy));
		return 0;
	}

	cache->core_conf_meta[core_id].seq_cutoff_policy = policy;

	ocf_core_log(core, log_info,
			"Changing sequential cutoff policy from %s to %s\n",
			_cache_mng_seq_cutoff_policy_get_name(policy_old),
			_cache_mng_seq_cutoff_policy_get_name(policy));

	return 0;
}

int ocf_mngt_core_set_seq_cutoff_policy(ocf_core_t core,
		ocf_seq_cutoff_policy policy)
{
	OCF_CHECK_NULL(core);

	return _cache_mng_set_core_seq_cutoff_policy(core, &policy);
}
int ocf_mngt_core_set_seq_cutoff_policy_all(ocf_cache_t cache,
		ocf_seq_cutoff_policy policy)
{
	OCF_CHECK_NULL(cache);

	return ocf_core_visit(cache, _cache_mng_set_core_seq_cutoff_policy,
			&policy, true);
}

int ocf_mngt_core_get_seq_cutoff_policy(ocf_core_t core,
		ocf_seq_cutoff_policy *policy)
{
	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(policy);

	*policy = ocf_core_get_seq_cutoff_policy(core);

	return 0;
}
