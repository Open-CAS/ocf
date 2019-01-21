/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "metadata/metadata.h"
#include "engine/cache_engine.h"
#include "utils/utils_cache_line.h"
#include "ocf_priv.h"
#include "ocf_cache_priv.h"

ocf_data_obj_t ocf_cache_get_data_object(ocf_cache_t cache)
{
	return ocf_cache_is_device_attached(cache) ? &cache->device->obj : NULL;
}

ocf_cache_id_t ocf_cache_get_id(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return cache->cache_id;
}

int ocf_cache_set_name(ocf_cache_t cache, const char *src, size_t src_size)
{
	OCF_CHECK_NULL(cache);
	return env_strncpy(cache->name, sizeof(cache->name), src, src_size);
}

const char *ocf_cache_get_name(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return cache->name;
}

bool ocf_cache_is_incomplete(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return env_bit_test(ocf_cache_state_incomplete, &cache->cache_state);
}

bool ocf_cache_is_running(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return env_bit_test(ocf_cache_state_running, &cache->cache_state);
}

bool ocf_cache_is_device_attached(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return env_atomic_read(&(cache)->attached);
}

ocf_cache_mode_t ocf_cache_get_mode(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return cache->conf_meta->cache_mode;
}

static uint32_t _calc_dirty_for(uint64_t dirty_since)
{
	return dirty_since ?
		(env_ticks_to_msecs(env_get_tick_count() - dirty_since) / 1000)
		: 0;
}

int ocf_cache_get_info(ocf_cache_t cache, struct ocf_cache_info *info)
{
	uint32_t i;
	uint32_t cache_occupancy_total = 0;
	uint32_t dirty_blocks_total = 0;
	uint32_t initial_dirty_blocks_total = 0;
	uint32_t flushed_total = 0;
	uint32_t curr_dirty_cnt;
	uint64_t dirty_since = 0;
	uint32_t init_dirty_cnt;
	uint64_t core_dirty_since;
	uint32_t dirty_blocks_inactive = 0;
	uint32_t cache_occupancy_inactive = 0;

	OCF_CHECK_NULL(cache);

	if (!info)
		return -OCF_ERR_INVAL;

	ENV_BUG_ON(env_memset(info, sizeof(*info), 0));

	info->attached = ocf_cache_is_device_attached(cache);
	if (info->attached) {
		info->data_obj_type = ocf_ctx_get_data_obj_type_id(cache->owner,
				cache->device->obj.type);
		info->size = cache->conf_meta->cachelines;
	}
	info->core_count = cache->conf_meta->core_count;

	info->cache_mode = ocf_cache_get_mode(cache);

	/* iterate through all possibly valid core objcts, as list of
	 * valid objects may be not continuous
	 */
	for (i = 0; i != OCF_CORE_MAX; ++i) {
		if (!env_bit_test(i, cache->conf_meta->valid_object_bitmap))
			continue;

		/* If current dirty blocks exceeds saved initial dirty
		 * blocks then update the latter
		 */
		curr_dirty_cnt = env_atomic_read(&cache->
				core_runtime_meta[i].dirty_clines);
		init_dirty_cnt = env_atomic_read(&cache->
				core_runtime_meta[i].initial_dirty_clines);
		if (init_dirty_cnt &&
				(curr_dirty_cnt > init_dirty_cnt)) {
			env_atomic_set(
				&cache->core_runtime_meta[i].
					initial_dirty_clines,
				env_atomic_read(&cache->
					core_runtime_meta[i].dirty_clines));
		}
		cache_occupancy_total += env_atomic_read(&cache->
				core_runtime_meta[i].cached_clines);

		dirty_blocks_total += env_atomic_read(&(cache->
				core_runtime_meta[i].dirty_clines));
		initial_dirty_blocks_total += env_atomic_read(&(cache->
				core_runtime_meta[i].initial_dirty_clines));

		if (!cache->core[i].opened) {
			cache_occupancy_inactive += env_atomic_read(&cache->
				core_runtime_meta[i].cached_clines);

			dirty_blocks_inactive += env_atomic_read(&(cache->
				core_runtime_meta[i].dirty_clines));
		}
		core_dirty_since = env_atomic64_read(&cache->
				core_runtime_meta[i].dirty_since);
		if (core_dirty_since) {
			dirty_since = (dirty_since ?
				OCF_MIN(dirty_since, core_dirty_since) :
				core_dirty_since);
		}

		flushed_total += env_atomic_read(
				&cache->core[i].flushed);
	}

	info->dirty = dirty_blocks_total;
	info->dirty_initial = initial_dirty_blocks_total;
	info->occupancy = cache_occupancy_total;
	info->dirty_for = _calc_dirty_for(dirty_since);
	info->metadata_end_offset = ocf_cache_is_device_attached(cache) ?
			cache->device->metadata_offset_line : 0;

	info->state = cache->cache_state;
	info->inactive.occupancy = cache_occupancy_inactive;
	info->inactive.dirty = dirty_blocks_inactive;
	info->flushed = (env_atomic_read(&cache->flush_in_progress)) ?
			flushed_total : 0;

	info->fallback_pt.status = ocf_fallback_pt_is_on(cache);
	info->fallback_pt.error_counter =
		env_atomic_read(&cache->fallback_pt_error_counter);

	info->eviction_policy = cache->conf_meta->eviction_policy_type;
	info->cleaning_policy = cache->conf_meta->cleaning_policy_type;
	info->metadata_footprint = ocf_cache_is_device_attached(cache) ?
			ocf_metadata_size_of(cache) : 0;
	info->cache_line_size = ocf_line_size(cache);

	return 0;
}

const struct ocf_data_obj_uuid *ocf_cache_get_uuid(ocf_cache_t cache)
{
	if (!ocf_cache_is_device_attached(cache))
		return NULL;

	return ocf_dobj_get_uuid(ocf_cache_get_data_object(cache));
}

uint8_t ocf_cache_get_type_id(ocf_cache_t cache)
{
	if (!ocf_cache_is_device_attached(cache))
		return 0xff;

	return ocf_ctx_get_data_obj_type_id(ocf_cache_get_ctx(cache),
		ocf_dobj_get_type(ocf_cache_get_data_object(cache)));
}

ocf_cache_line_size_t ocf_cache_get_line_size(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return ocf_line_size(cache);
}

uint64_t ocf_cache_bytes_2_lines(ocf_cache_t cache, uint64_t bytes)
{
	OCF_CHECK_NULL(cache);
	return ocf_bytes_2_lines(cache, bytes);
}

uint32_t ocf_cache_get_core_count(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return cache->conf_meta->core_count;
}

ocf_ctx_t ocf_cache_get_ctx(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return cache->owner;
}
