/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "metadata/metadata.h"
#include "metadata/metadata.h"
#include "engine/cache_engine.h"
#include "utils/utils_cache_line.h"
#include "ocf_request.h"
#include "utils/utils_user_part.h"
#include "ocf_priv.h"
#include "ocf_cache_priv.h"
#include "ocf_queue_priv.h"
#include "utils/utils_stats.h"
#include "ocf/ocf_debug.h"

ocf_volume_t ocf_cache_get_volume(ocf_cache_t cache)
{
	return cache->device ? &cache->device->volume : NULL;
}

ocf_volume_t ocf_cache_get_front_volume(ocf_cache_t cache)
{
	return cache->device ? &cache->device->front_volume : NULL;
}

uint32_t ocf_cache_get_queue_count(ocf_cache_t cache)
{
	ocf_queue_t queue = NULL;
	uint32_t cnt = 0;

	list_for_each_entry(queue, &cache->io_queues, list)
		cnt++;

	return cnt;
}

int ocf_cache_set_name(ocf_cache_t cache, const char *src, size_t src_size)
{
	int result;

	OCF_CHECK_NULL(cache);

	result = env_strncpy(cache->name, OCF_CACHE_NAME_SIZE, src, src_size);
	if (result)
		return result;

	return env_strncpy(cache->conf_meta->name, OCF_CACHE_NAME_SIZE,
			src, src_size);
}

bool ocf_cache_mode_is_valid(ocf_cache_mode_t mode)
{
	return mode >= ocf_cache_mode_wt && mode < ocf_cache_mode_max;
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

bool ocf_cache_is_detached(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return env_bit_test(ocf_cache_state_detached, &cache->cache_state);
}

bool ocf_cache_is_standby(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return env_bit_test(ocf_cache_state_standby, &cache->cache_state);
}

bool ocf_cache_is_device_attached(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return !!cache->device;
}

ocf_cache_mode_t ocf_cache_get_mode(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

	return cache->conf_meta->cache_mode;
}

static uint64_t _calc_dirty_for(uint64_t dirty_since)
{
	uint64_t current_time = env_ticks_to_secs(env_get_tick_count());

	return dirty_since ? (current_time - dirty_since) : 0;
}

int ocf_cache_get_info(ocf_cache_t cache, struct ocf_cache_info *info)
{
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
	ocf_core_t core;
	ocf_core_id_t core_id;

	OCF_CHECK_NULL(cache);

	if (!info)
		return -OCF_ERR_INVAL;

	ENV_BUG_ON(env_memset(info, sizeof(*info), 0));

	_ocf_stats_zero(&info->inactive);

	info->attached = ocf_cache_is_device_attached(cache);
	info->standby_detached = ocf_cache_is_standby(cache) &&
		ocf_refcnt_frozen(&cache->refcnt.metadata);
	if (info->attached && !info->standby_detached) {
		info->volume_type = ocf_ctx_get_volume_type_id(cache->owner,
				cache->device->volume.type);
		info->size = cache->conf_meta->cachelines;
	}
	info->state = cache->cache_state;
	info->cache_line_size = ocf_line_size(cache);
	info->metadata_end_offset = ocf_cache_is_device_attached(cache) ?
			cache->device->metadata_offset / PAGE_SIZE : 0;
	info->metadata_footprint = ocf_cache_is_device_attached(cache) ?
			ocf_metadata_size_of(cache) : 0;

	if (ocf_cache_is_standby(cache))
		return 0;

	info->core_count = cache->conf_meta->core_count;

	info->cache_mode = ocf_cache_get_mode(cache);

	/* iterate through all possibly valid core objcts, as list of
	 * valid objects may be not continuous
	 */
	for_each_core(cache, core, core_id) {
		/* If current dirty blocks exceeds saved initial dirty
		 * blocks then update the latter
		 */
		curr_dirty_cnt = env_atomic_read(
				&core->runtime_meta->dirty_clines);
		init_dirty_cnt = env_atomic_read(
				&core->runtime_meta->initial_dirty_clines);
		if (init_dirty_cnt && (curr_dirty_cnt > init_dirty_cnt)) {
			env_atomic_set(
				&core->runtime_meta->initial_dirty_clines,
				env_atomic_read(
					&core->runtime_meta->dirty_clines));
		}
		cache_occupancy_total += env_atomic_read(
				&core->runtime_meta->cached_clines);

		dirty_blocks_total += env_atomic_read(
				&core->runtime_meta->dirty_clines);
		initial_dirty_blocks_total += env_atomic_read(
				&core->runtime_meta->initial_dirty_clines);

		if (!core->opened) {
			cache_occupancy_inactive += env_atomic_read(
				&core->runtime_meta->cached_clines);

			dirty_blocks_inactive += env_atomic_read(
				&core->runtime_meta->dirty_clines);
		}
		core_dirty_since = env_atomic64_read(
				&core->runtime_meta->dirty_since);
		if (core_dirty_since) {
			dirty_since = (dirty_since ?
				OCF_MIN(dirty_since, core_dirty_since) :
				core_dirty_since);
		}

		flushed_total += env_atomic_read(&core->flushed);
	}

	info->dirty = dirty_blocks_total;
	info->dirty_initial = initial_dirty_blocks_total;
	info->occupancy = cache_occupancy_total;
	info->dirty_for = _calc_dirty_for(dirty_since);

	if (info->attached) {
		_set(&info->inactive.occupancy,
				_lines4k(cache_occupancy_inactive, ocf_line_size(cache)),
				_lines4k(info->size, ocf_line_size(cache)));
		_set(&info->inactive.clean,
				_lines4k(cache_occupancy_inactive - dirty_blocks_inactive,
					ocf_line_size(cache)),
				_lines4k(cache_occupancy_total, ocf_line_size(cache)));
		_set(&info->inactive.dirty,
				_lines4k(dirty_blocks_inactive, ocf_line_size(cache)),
				_lines4k(cache_occupancy_total, ocf_line_size(cache)));
	}

	info->flushed = (env_atomic_read(&cache->flush_in_progress)) ?
			flushed_total : 0;

	info->fallback_pt.status = ocf_fallback_pt_is_on(cache);
	info->fallback_pt.error_counter =
		env_atomic_read(&cache->fallback_pt_error_counter);

	info->cleaning_policy = cache->cleaner.policy;
	info->promotion_policy = cache->conf_meta->promotion_policy_type;
	info->cache_line_size = ocf_line_size(cache);

	return 0;
}

const struct ocf_volume_uuid *ocf_cache_get_uuid(ocf_cache_t cache)
{
	if (!ocf_cache_is_device_attached(cache))
		return NULL;

	return ocf_volume_get_uuid(ocf_cache_get_volume(cache));
}

uint8_t ocf_cache_get_type_id(ocf_cache_t cache)
{
	if (!ocf_cache_is_device_attached(cache))
		return 0xff;

	return ocf_ctx_get_volume_type_id(ocf_cache_get_ctx(cache),
		ocf_volume_get_type(ocf_cache_get_volume(cache)));
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

void ocf_cache_set_priv(ocf_cache_t cache, void *priv)
{
	OCF_CHECK_NULL(cache);
	cache->priv = priv;
}

void *ocf_cache_get_priv(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return cache->priv;
}

struct ocf_cache_volume {
	ocf_cache_t cache;
};

static inline ocf_cache_t ocf_volume_to_cache(ocf_volume_t volume)
{
	struct ocf_cache_volume *cache_volume = ocf_volume_get_priv(volume);

	return cache_volume->cache;
}

static void ocf_cache_volume_io_complete_generic(struct ocf_request *req,
		int error)
{
	ocf_cache_t cache = req->cache;

	ocf_refcnt_dec(&cache->refcnt.metadata);
	ocf_io_end_func(req, error);
}

static void ocf_cache_io_complete(struct ocf_request *req, int error)
{
	ocf_cache_t cache = req->cache;

	if (error)
		req->error = req->error ?: error;

	if (env_atomic_dec_return(&req->req_remaining))
		return;

	ocf_refcnt_dec(&cache->refcnt.metadata);
	ocf_io_end_func(req, req->error);
}

static void ocf_cache_volume_submit_io(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	ocf_cache_t cache = req->cache;
	int result;

	if (!ocf_refcnt_inc(&cache->refcnt.metadata)) {
		ocf_io_end_func(io, -OCF_ERR_IO);
		return;
	}
	if (unlikely(!ocf_cache_is_standby(cache))) {
		ocf_io_end_func(io, -OCF_ERR_CACHE_NOT_STANDBY);
		return;
	}

	env_atomic_set(&req->req_remaining, 3);

	req->cache_forward_end = ocf_cache_io_complete;
	ocf_req_forward_cache_io(req, req->rw, req->byte_position,
			req->byte_length, req->offset);

	req->complete = ocf_cache_io_complete;
	result = ocf_metadata_passive_update(req);
	if (result) {
		ocf_cache_log(cache, log_crit,
				"Metadata update error (error=%d)!\n", result);
	}

	// TODO why the result is not passed to io_cmpl???
	ocf_cache_io_complete(req, 0);
}

static void ocf_cache_volume_submit_flush(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	ocf_cache_t cache = req->cache;

	if (!ocf_refcnt_inc(&cache->refcnt.metadata)) {
		ocf_io_end_func(io, -OCF_ERR_IO);
		return;
	}
	if (unlikely(!ocf_cache_is_standby(cache))) {
		ocf_io_end_func(io, -OCF_ERR_CACHE_NOT_STANDBY);
		return;
	}

	req->cache_forward_end = ocf_cache_volume_io_complete_generic;
	ocf_req_forward_cache_flush(req);
}


static void ocf_cache_volume_submit_discard(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	ocf_cache_t cache = req->cache;

	if (!ocf_refcnt_inc(&cache->refcnt.metadata)) {
		ocf_io_end_func(io, -OCF_ERR_IO);
		return;
	}
	if (unlikely(!ocf_cache_is_standby(cache))) {
		ocf_io_end_func(io, -OCF_ERR_CACHE_NOT_STANDBY);
		return;
	}

	req->cache_forward_end = ocf_cache_volume_io_complete_generic;
	ocf_req_forward_cache_discard(req, req->byte_position,
			req->byte_length);
}

/* *** VOLUME OPS *** */

static int ocf_cache_volume_open(ocf_volume_t volume, void *volume_params)
{
	struct ocf_cache_volume *cache_volume = ocf_volume_get_priv(volume);
	const struct ocf_volume_uuid *uuid = ocf_volume_get_uuid(volume);
	ocf_cache_t cache = (ocf_cache_t)uuid->data;

	cache_volume->cache = cache;

	return 0;
}

static void ocf_cache_volume_close(ocf_volume_t volume)
{
	struct ocf_cache_volume *cache_volume = ocf_volume_get_priv(volume);

	cache_volume->cache = NULL;
}

static unsigned int ocf_cache_volume_get_max_io_size(ocf_volume_t volume)
{
	ocf_cache_t cache = ocf_volume_to_cache(volume);

	return ocf_volume_get_max_io_size(ocf_cache_get_volume(cache));
}

static uint64_t ocf_cache_volume_get_byte_length(ocf_volume_t volume)
{
	ocf_cache_t cache = ocf_volume_to_cache(volume);

	return ocf_volume_get_length(ocf_cache_get_volume(cache));
}

const struct ocf_volume_properties ocf_cache_volume_properties = {
	.name = "OCF_Cache",
	.volume_priv_size = sizeof(struct ocf_cache_volume),
	.caps = {
		.atomic_writes = 0,
	},
	.ops = {
		.submit_io = ocf_cache_volume_submit_io,
		.submit_flush = ocf_cache_volume_submit_flush,
		.submit_discard = ocf_cache_volume_submit_discard,
		.submit_metadata = NULL,

		.open = ocf_cache_volume_open,
		.close = ocf_cache_volume_close,
		.get_max_io_size = ocf_cache_volume_get_max_io_size,
		.get_length = ocf_cache_volume_get_byte_length,
	},
	.deinit = NULL,
};

static int ocf_cache_io_allocator_init(ocf_io_allocator_t allocator,
		const char *name)
{
	return 0;
}

static void ocf_cache_io_allocator_deinit(ocf_io_allocator_t allocator)
{
}

static void *ocf_cache_io_allocator_new(ocf_io_allocator_t allocator,
		ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir)
{
	ocf_cache_t cache = ocf_volume_to_cache(volume);

	return ocf_req_new_cache(cache, queue, addr, bytes, dir);
}

static void ocf_cache_io_allocator_del(ocf_io_allocator_t allocator, void *obj)
{
	struct ocf_request *req = obj;

	ocf_req_put(req);
}

const struct ocf_io_allocator_type ocf_cache_io_allocator_type = {
	.ops = {
		.allocator_init = ocf_cache_io_allocator_init,
		.allocator_deinit = ocf_cache_io_allocator_deinit,
		.allocator_new = ocf_cache_io_allocator_new,
		.allocator_del = ocf_cache_io_allocator_del,
	},
};

const struct ocf_volume_extended ocf_cache_volume_extended = {
	.allocator_type = &ocf_cache_io_allocator_type,
};

int ocf_cache_volume_type_init(ocf_ctx_t ctx)
{
	return ocf_ctx_register_volume_type_internal(ctx, OCF_VOLUME_TYPE_CACHE,
			&ocf_cache_volume_properties,
			&ocf_cache_volume_extended);
}

bool ocf_dbg_cache_is_settled(ocf_cache_t cache)
{
	return ocf_refcnt_zeroed(&cache->refcnt.metadata) &&
			ocf_refcnt_zeroed(&cache->refcnt.d2c);
}
