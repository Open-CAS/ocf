/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_mngt_common.h"
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
	struct ocf_core *core_obj;
	ocf_data_obj_t obj;

	core_obj = &cache->core_obj[cfg->core_id];
	obj = &core_obj->obj;

	if (ocf_ctx_get_data_obj_type_id(cache->owner, obj->type) !=
				cfg->data_obj_type) {
		result = -OCF_ERR_INVAL_DATA_OBJ_TYPE;
		goto error_out;
	}

	result = ocf_data_obj_open(obj);
	if (result)
		goto error_out;

	if (!ocf_data_obj_get_length(obj)) {
		result = -OCF_ERR_CORE_NOT_AVAIL;
		goto error_after_open;
	}

	cache->core_obj[cfg->core_id].opened = true;

	if (!(--cache->ocf_core_inactive_count))
		env_bit_clear(ocf_cache_state_incomplete, &cache->cache_state);

	*core = core_obj;
	return 0;

error_after_open:
	ocf_data_obj_close(obj);
error_out:
	*core = NULL;
	return result;
}

static int _ocf_mngt_cache_add_core(ocf_cache_t cache, ocf_core_t *core,
		struct ocf_mngt_core_config *cfg)
{
	int result = 0;
	struct ocf_core *core_obj;
	ocf_data_obj_t obj;
	ocf_seq_no_t core_sequence_no;
	ocf_cleaning_t clean_type;
	uint64_t length;

	core_obj = &cache->core_obj[cfg->core_id];
	obj = &core_obj->obj;

	core_obj->obj.cache = cache;

	/* Set uuid */
	ocf_uuid_core_set(cache, core_obj, &cfg->uuid);

	obj->type = ocf_ctx_get_data_obj_type(cache->owner, cfg->data_obj_type);
	if (!obj->type) {
		result = -OCF_ERR_INVAL_DATA_OBJ_TYPE;
		goto error_out;
	}

	if (cfg->user_metadata.data && cfg->user_metadata.size > 0) {
		result = ocf_core_set_user_metadata_raw(core_obj,
				cfg->user_metadata.data,
				cfg->user_metadata.size);
		if (result)
			goto error_out;
	}

	result = ocf_data_obj_open(obj);
	if (result)
		goto error_out;

	length = ocf_data_obj_get_length(obj);
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
	core_obj->counters =
		env_zalloc(sizeof(*core_obj->counters), ENV_MEM_NORMAL);
	if (!core_obj->counters) {
		result = -OCF_ERR_NO_MEM;
		goto error_after_clean_pol;
	}
	/* When adding new core to cache, reset all core/cache statistics */
	ocf_stats_init(core_obj);
	env_atomic_set(&cache->core_runtime_meta[cfg->core_id].
			cached_clines, 0);
	env_atomic_set(&cache->core_runtime_meta[cfg->core_id].
			dirty_clines, 0);
	env_atomic64_set(&cache->core_runtime_meta[cfg->core_id].
			dirty_since, 0);

	/* In metadata mark data this core was added into cache */
	env_bit_set(cfg->core_id, cache->conf_meta->valid_object_bitmap);
	cache->core_conf_meta[cfg->core_id].added = true;
	cache->core_obj[cfg->core_id].opened = true;

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
	cache->conf_meta->core_obj_count++;

	*core = core_obj;
	return 0;

error_after_counters_allocation:
	env_bit_clear(cfg->core_id, cache->conf_meta->valid_object_bitmap);
	cache->core_conf_meta[cfg->core_id].added = false;
	cache->core_obj[cfg->core_id].opened = false;

	/* An error when flushing metadata, try restore for safety reason
	 * previous metadata sate on cache device.
	 * But if that fails too, we are scr**ed... or maybe:
	 * TODO: Handle situation when we can't flush metadata by
	 * trying to flush all the dirty data and switching to non-wb
	 * cache mode.
	 */
	ocf_metadata_flush_superblock(cache);

	env_free(core_obj->counters);
	core_obj->counters = NULL;

error_after_clean_pol:
	 if (cleaning_policy_ops[clean_type].remove_core)
		cleaning_policy_ops[clean_type].remove_core(cache, cfg->core_id);

error_after_open:
	ocf_data_obj_close(obj);
error_out:
	ocf_uuid_core_clear(cache, core_obj);
	*core = NULL;
	return result;
}

static unsigned long _ffz(unsigned long word)
{
	asm("rep; bsf %1,%0"
			: "=r" (word)
			: "r" (~word));
	return word;
}

static unsigned long _ocf_mngt_find_first_free_core(const unsigned long *bitmap,
		unsigned long size)
{
	unsigned long i;
	unsigned long ret = size;

	/* check core 0 availability */
	bool zero_core_free = !(*bitmap & 0x1UL);

	/* check if any core id is free except 0 */
	for (i = 0; i * sizeof(unsigned long) * 8 < size; i++) {
		unsigned long long ignore_mask = (i == 0) ? 1UL : 0UL;
		if (~(bitmap[i] | ignore_mask)) {
			ret = MIN(size, i * sizeof(unsigned long) * 8 +
				  _ffz(bitmap[i] | ignore_mask));
			break;
		}
	}

	/* return 0 only if no other core is free */
	if (ret == size && zero_core_free)
		return 0;

	return ret;
}

static int __ocf_mngt_lookup_core_uuid(ocf_cache_t cache,
		struct ocf_mngt_core_config *cfg)
{
	int i;

	for (i = 0; i < OCF_CORE_MAX; i++) {
		ocf_core_t core = &cache->core_obj[i];

		if (!env_bit_test(i, cache->conf_meta->valid_object_bitmap))
			continue;

		if (cache->core_obj[i].opened)
			continue;

		if (ocf_ctx_get_data_obj_type_id(cache->owner, core->obj.type)
				!= cfg->data_obj_type) {
			continue;
		}

		if (!env_strncmp(core->obj.uuid.data, cfg->uuid.data,
				min(core->obj.uuid.size,
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
				cache->conf_meta->valid_object_bitmap,
				OCF_CORE_MAX);
		/* no need to check if find_first_zero_bit failed and
		 * *core_id == MAX_CORE_OBJS_PER_CACHE, as above there is check
		 * for core_obj_count being greater or equal to
		 * MAX_CORE_OBJS_PER_CACHE
		 */
	} else if (cfg->core_id < OCF_CORE_MAX) {
		/* check if id is not used already */
		if (env_bit_test(cfg->core_id,
				cache->conf_meta->valid_object_bitmap)) {
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

	if (cache->conf_meta->core_obj_count >= OCF_CORE_MAX)
		return -OCF_ERR_TOO_MANY_CORES;

	tmp_core_id = __ocf_mngt_lookup_core_uuid(cache, cfg);

	if (cfg->try_add)
		result = __ocf_mngt_try_find_core_id(cache, cfg, tmp_core_id);
	else
		result = __ocf_mngt_find_core_id(cache, cfg, tmp_core_id);

	return result;
}

int ocf_mngt_cache_add_core_nolock(ocf_cache_t cache, ocf_core_t *core,
		struct ocf_mngt_core_config *cfg)
{
	int result;
	char core_name[OCF_CORE_NAME_SIZE];

	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(core);

	result = _ocf_mngt_find_core_id(cache, cfg);
	if (result)
		return result;

	if (cfg->name) {
		result = env_strncpy(core_name, sizeof(core_name), cfg->name,
				cfg->name_size);
		if (result)
			return result;
	} else {
		result = snprintf(core_name, sizeof(core_name), "%hu",
				cfg->core_id);
		if (result < 0)
			return result;
	}

	result = ocf_core_set_name(&cache->core_obj[cfg->core_id], core_name,
			sizeof(core_name));
	if (result)
		return result;

	ocf_cache_log(cache, log_debug, "Inserting core %s\n", core_name);

	if (cfg->try_add)
		result = _ocf_mngt_cache_try_add_core(cache, core, cfg);
	else
		result = _ocf_mngt_cache_add_core(cache, core, cfg);

	if (!result) {
		ocf_core_log(*core, log_info, "Successfully added\n");
	} else {
		if (result == -OCF_ERR_CORE_NOT_AVAIL) {
			ocf_cache_log(cache, log_err, "Core %s is zero size\n",
					core_name);
		}
		ocf_cache_log(cache, log_err, "Adding core %s failed\n",
				core_name);
	}

	return result;
}

int ocf_mngt_cache_add_core(ocf_cache_t cache, ocf_core_t *core,
		struct ocf_mngt_core_config *cfg)
{
	int result;

	OCF_CHECK_NULL(cache);

	result = ocf_mngt_cache_lock(cache);
	if (result)
		return result;

	result = ocf_mngt_cache_add_core_nolock(cache, core, cfg);

	ocf_mngt_cache_unlock(cache);

	return result;
}

static int _ocf_mngt_cache_remove_core(ocf_core_t core, bool detach)
{
	struct ocf_cache *cache = core->obj.cache;
	ocf_core_id_t core_id = ocf_core_get_id(core);
	int status;

	if (detach) {
		status = cache_mng_core_close(cache, core_id);
		if (!status) {
			cache->ocf_core_inactive_count++;
			env_bit_set(ocf_cache_state_incomplete,
					&cache->cache_state);
		}
		return status;
	}

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

int ocf_mngt_cache_remove_core_nolock(ocf_cache_t cache, ocf_core_id_t core_id,
		bool detach)
{
	int result;
	ocf_core_t core;
	const char *core_name;

	OCF_CHECK_NULL(cache);

	result = ocf_core_get(cache, core_id, &core);
	if (result < 0)
		return -OCF_ERR_CORE_NOT_AVAIL;

	ocf_core_log(core, log_debug, "Removing core\n");

	core_name = ocf_core_get_name(core);

	result = _ocf_mngt_cache_remove_core(core, detach);
	if (!result) {
		ocf_cache_log(cache, log_info, "Core %s successfully removed\n",
				core_name);
	} else {
		ocf_cache_log(cache, log_err, "Removing core %s failed\n",
				core_name);
	}

	return result;
}

int ocf_mngt_cache_remove_core(ocf_cache_t cache, ocf_core_id_t core_id,
		bool detach)
{
	int result;

	OCF_CHECK_NULL(cache);

	result = ocf_mngt_cache_lock(cache);
	if (result)
		return result;

	result = ocf_mngt_cache_remove_core_nolock(cache, core_id, detach);

	ocf_mngt_cache_unlock(cache);

	return result;
}
