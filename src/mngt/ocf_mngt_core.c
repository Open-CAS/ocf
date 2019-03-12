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

	result = ocf_volume_open(volume);
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

static int _ocf_mngt_cache_add_core(ocf_cache_t cache, ocf_core_t *core,
		struct ocf_mngt_core_config *cfg)
{
	ocf_core_t tmp_core;
	struct ocf_volume_uuid new_uuid;
	ocf_volume_t volume;
	ocf_volume_type_t type;
	ocf_seq_no_t core_sequence_no;
	ocf_cleaning_t clean_type;
	uint64_t length;
	int result = 0;

	tmp_core = &cache->core[cfg->core_id];
	volume = &tmp_core->volume;

	tmp_core->volume.cache = cache;

	/* Set uuid */
	result = ocf_metadata_set_core_uuid(tmp_core, &cfg->uuid, &new_uuid);
	if (result)
		return -OCF_ERR_INVAL;

	type = ocf_ctx_get_volume_type(cache->owner, cfg->volume_type);
	if (!type) {
		result = -OCF_ERR_INVAL_VOLUME_TYPE;
		goto error_out;
	}

	result = ocf_volume_init(volume, type, &new_uuid, false);
	if (result)
		goto error_out;

	if (cfg->user_metadata.data && cfg->user_metadata.size > 0) {
		result = ocf_mngt_core_set_user_metadata(tmp_core,
				cfg->user_metadata.data,
				cfg->user_metadata.size);
		if (result)
			goto error_out;
	}

	result = ocf_volume_open(volume);
	if (result)
		goto error_out;

	length = ocf_volume_get_length(volume);
	if (!length) {
		result = -OCF_ERR_CORE_NOT_AVAIL;
		goto error_after_open;
	}
	cache->core_conf_meta[cfg->core_id].length = length;

	clean_type = cache->conf_meta->cleaning_policy_type;
	if (ocf_cache_is_device_attached(cache) &&
			cleaning_policy_ops[clean_type].add_core) {
		result = cleaning_policy_ops[clean_type].add_core(cache,
				cfg->core_id);
		if (result)
			goto error_after_open;
	}

	/* When adding new core to cache, allocate stat counters */
	tmp_core->counters =
		env_zalloc(sizeof(*tmp_core->counters), ENV_MEM_NORMAL);
	if (!tmp_core->counters) {
		result = -OCF_ERR_NO_MEM;
		goto error_after_clean_pol;
	}
	/* When adding new core to cache, reset all core/cache statistics */
	ocf_core_stats_initialize(tmp_core);
	env_atomic_set(&cache->core_runtime_meta[cfg->core_id].
			cached_clines, 0);
	env_atomic_set(&cache->core_runtime_meta[cfg->core_id].
			dirty_clines, 0);
	env_atomic64_set(&cache->core_runtime_meta[cfg->core_id].
			dirty_since, 0);

	/* In metadata mark data this core was added into cache */
	env_bit_set(cfg->core_id, cache->conf_meta->valid_core_bitmap);
	cache->core_conf_meta[cfg->core_id].added = true;
	tmp_core->opened = true;

	/* Set default cache parameters for sequential */
	cache->core_conf_meta[cfg->core_id].seq_cutoff_policy =
		ocf_seq_cutoff_policy_default;
	cache->core_conf_meta[cfg->core_id].seq_cutoff_threshold =
		cfg->seq_cutoff_threshold;

	/* Add core sequence number for atomic metadata matching */
	core_sequence_no = _ocf_mngt_get_core_seq_no(cache);
	if (core_sequence_no == OCF_SEQ_NO_INVALID) {
		result = -OCF_ERR_TOO_MANY_CORES;
		goto error_after_counters_allocation;
	}
	cache->core_conf_meta[cfg->core_id].seq_no = core_sequence_no;

	/* Update super-block with core device addition */
	if (ocf_metadata_flush_superblock(cache)) {
		result = -OCF_ERR_WRITE_CACHE;
		goto error_after_counters_allocation;
	}

	/* Increase value of added cores */
	cache->conf_meta->core_count++;

	*core = tmp_core;
	return 0;

error_after_counters_allocation:
	env_bit_clear(cfg->core_id, cache->conf_meta->valid_core_bitmap);
	cache->core_conf_meta[cfg->core_id].added = false;
	tmp_core->opened = false;

	/* An error when flushing metadata, try restore for safety reason
	 * previous metadata sate on cache device.
	 * But if that fails too, we are scr**ed... or maybe:
	 * TODO: Handle situation when we can't flush metadata by
	 * trying to flush all the dirty data and switching to non-wb
	 * cache mode.
	 */
	ocf_metadata_flush_superblock(cache);

	env_free(tmp_core->counters);
	tmp_core->counters = NULL;

error_after_clean_pol:
	if (cleaning_policy_ops[clean_type].remove_core)
		cleaning_policy_ops[clean_type].remove_core(cache, cfg->core_id);

error_after_open:
	ocf_volume_close(volume);
error_out:
	ocf_metadata_clear_core_uuid(tmp_core);
	*core = NULL;
	return result;
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

	return ocf_volume_open(&core->front_volume);
}

void ocf_mngt_cache_add_core(ocf_cache_t cache,
		struct ocf_mngt_core_config *cfg,
		ocf_mngt_cache_add_core_end_t cmpl, void *priv)
{
	char core_name[OCF_CORE_NAME_SIZE];
	ocf_core_t core = NULL;
	int result;

	OCF_CHECK_NULL(cache);

	result = _ocf_mngt_find_core_id(cache, cfg);
	if (result) {
		cmpl(cache, NULL, priv, result);
		return;
	}

	if (cfg->name) {
		result = env_strncpy(core_name, sizeof(core_name), cfg->name,
				sizeof(core_name));
		if (result) {
			cmpl(cache, NULL, priv, result);
			return;
		}
	} else {
		result = snprintf(core_name, sizeof(core_name), "core%hu",
				cfg->core_id);
		if (result < 0) {
			cmpl(cache, NULL, priv, result);
			return;
		}
	}

	result = ocf_core_set_name(&cache->core[cfg->core_id], core_name,
			sizeof(core_name));
	if (result) {
		cmpl(cache, NULL, priv, result);
		return;
	}

	ocf_cache_log(cache, log_debug, "Inserting core %s\n", core_name);

	if (cfg->try_add)
		result = _ocf_mngt_cache_try_add_core(cache, &core, cfg);
	else
		result = _ocf_mngt_cache_add_core(cache, &core, cfg);

	if (result)
		goto out;

	result = ocf_mngt_core_init_front_volume(core);

out:
	if (!result) {
		ocf_core_log(core, log_info, "Successfully added\n");
	} else {
		if (result == -OCF_ERR_CORE_NOT_AVAIL) {
			ocf_cache_log(cache, log_err, "Core %s is zero size\n",
					core_name);
		}
		ocf_cache_log(cache, log_err, "Adding core %s failed\n",
				core_name);
	}

	cmpl(cache, core, priv, result);
}

static int _ocf_mngt_cache_remove_core(ocf_core_t core)
{
	struct ocf_cache *cache = core->volume.cache;
	ocf_core_id_t core_id = ocf_core_get_id(core);

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
	ocf_metadata_flush_superblock(cache);

	return 0;
}

void ocf_mngt_cache_remove_core(ocf_core_t core,
		ocf_mngt_cache_remove_core_end_t cmpl, void *priv)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	const char *core_name = ocf_core_get_name(core);
	int result;

	ocf_core_log(core, log_debug, "Removing core\n");

	core_name = ocf_core_get_name(core);

	result = _ocf_mngt_cache_remove_core(core);
	if (!result) {
		ocf_cache_log(cache, log_info, "Core %s successfully removed\n",
				core_name);
	} else {
		ocf_cache_log(cache, log_err, "Removing core %s failed\n",
				core_name);
	}

	cmpl(priv, result);
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
	ocf_cache_t cache = ocf_core_get_cache(core);
	const char *core_name = ocf_core_get_name(core);
	int result;

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
