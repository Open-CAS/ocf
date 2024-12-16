/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_env_refcnt.h"
#include "ocf_priv.h"
#include "ocf_core_priv.h"
#include "ocf_io_priv.h"
#include "metadata/metadata.h"
#include "engine/cache_engine.h"
#include "engine/engine_d2c.h"
#include "utils/utils_user_part.h"
#include "ocf_request.h"

struct ocf_core_volume {
	ocf_core_t core;
};

ocf_cache_t ocf_core_get_cache(ocf_core_t core)
{
	OCF_CHECK_NULL(core);
	return core->volume.cache;
}

ocf_volume_t ocf_core_get_volume(ocf_core_t core)
{
	OCF_CHECK_NULL(core);
	return &core->volume;
}

ocf_volume_t ocf_core_get_front_volume(ocf_core_t core)
{
	OCF_CHECK_NULL(core);
	return &core->front_volume;
}

ocf_core_id_t ocf_core_get_id(ocf_core_t core)
{
	struct ocf_cache *cache;
	ocf_core_id_t core_id;

	OCF_CHECK_NULL(core);

	cache = core->volume.cache;
	core_id = core - cache->core;

	return core_id;
}

int ocf_core_get_by_name(ocf_cache_t cache, const char *name, size_t name_len,
		ocf_core_t *core)
{
	ocf_core_t i_core;
	ocf_core_id_t i_core_id;

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	for_each_core(cache, i_core, i_core_id) {
		if (!env_strncmp(ocf_core_get_name(i_core), OCF_CORE_NAME_SIZE,
				name, name_len)) {
			*core = i_core;
			return 0;
		}
	}

	return -OCF_ERR_CORE_NOT_EXIST;
}

const char *ocf_core_get_name(ocf_core_t core)
{
	OCF_CHECK_NULL(core);

	return core->conf_meta->name;
}

ocf_core_state_t ocf_core_get_state(ocf_core_t core)
{
	OCF_CHECK_NULL(core);

	return core->opened ?
			ocf_core_state_active : ocf_core_state_inactive;
}

bool ocf_core_is_valid(ocf_cache_t cache, ocf_core_id_t id)
{
	OCF_CHECK_NULL(cache);

	if (id > OCF_CORE_ID_MAX)
		return false;

	if (!env_bit_test(id, cache->conf_meta->valid_core_bitmap))
		return false;

	return true;
}

uint32_t ocf_core_get_seq_cutoff_threshold(ocf_core_t core)
{
	return env_atomic_read(&core->conf_meta->seq_cutoff_threshold);
}

ocf_seq_cutoff_policy ocf_core_get_seq_cutoff_policy(ocf_core_t core)
{
	return env_atomic_read(&core->conf_meta->seq_cutoff_policy);
}

uint32_t ocf_core_get_seq_cutoff_promotion_count(ocf_core_t core)
{
	return env_atomic_read(&core->conf_meta->seq_cutoff_promo_count);
}

bool ocf_core_get_seq_cutoff_promote_on_threshold(ocf_core_t core)
{
	return env_atomic_read(&core->conf_meta->seq_cutoff_promote_on_threshold);
}

int ocf_core_visit(ocf_cache_t cache, ocf_core_visitor_t visitor, void *cntx,
		bool only_opened)
{
	ocf_core_id_t id;
	int result = 0;

	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!visitor)
		return -OCF_ERR_INVAL;

	for (id = 0; id < OCF_CORE_MAX; id++) {
		if (!env_bit_test(id, cache->conf_meta->valid_core_bitmap))
			continue;

		if (only_opened && !cache->core[id].opened)
			continue;

		result = visitor(&cache->core[id], cntx);
		if (result)
			break;
	}

	return result;
}

/* *** HELPER FUNCTIONS *** */

static uint64_t _calc_dirty_for(uint64_t dirty_since)
{
	uint64_t current_time = env_ticks_to_secs(env_get_tick_count());

	return dirty_since ? (current_time - dirty_since) : 0;
}

struct ocf_request *ocf_io_to_req(ocf_io_t io)
{
	return io;
}

static inline ocf_core_t ocf_volume_to_core(ocf_volume_t volume)
{
	struct ocf_core_volume *core_volume = ocf_volume_get_priv(volume);

	return core_volume->core;
}

static inline void dec_counter_if_req_was_dirty(struct ocf_request *req)
{
	if (!req->dirty)
		return;

	req->dirty = 0;
	env_refcnt_dec(&req->cache->refcnt.dirty);
}

static inline int ocf_core_validate_io(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	ocf_volume_t volume = ocf_io_get_volume(io);
	ocf_core_t core = ocf_volume_to_core(volume);

	if (req->addr + req->bytes > ocf_volume_get_length(volume))
		return -OCF_ERR_INVAL;

	if (req->io.io_class >= OCF_USER_IO_CLASS_MAX)
		return -OCF_ERR_INVAL;

	if (req->rw != OCF_READ && req->rw != OCF_WRITE)
		return -OCF_ERR_INVAL;

	if (!req->io_queue)
		return -OCF_ERR_INVAL;

	if (!req->io.end)
		return -OCF_ERR_INVAL;

	/* Core volume I/O must not be queued on management queue - this would
	 * break I/O accounting code, resulting in use-after-free type of errors
	 * after cache detach, core remove etc. */
	if (req->io_queue == ocf_core_get_cache(core)->mngt_queue)
		return -OCF_ERR_INVAL;

	return 0;
}

static void ocf_req_complete(struct ocf_request *req, int error)
{
	/* Complete IO */
	ocf_io_end_func(req, error);

	dec_counter_if_req_was_dirty(req);

	/* Invalidate OCF IO, it is not valid after completion */
	ocf_io_put(req);
}

static inline ocf_req_cache_mode_t _ocf_core_req_resolve_fast_mode(
		ocf_cache_t cache, struct ocf_request *req)
{
	switch (req->cache_mode) {
		case ocf_req_cache_mode_wb:
		case ocf_req_cache_mode_wo:
			return ocf_req_cache_mode_fast;
		default:
			break;
	}

	if (!cache->use_submit_io_fast)
		return ocf_req_cache_mode_max;

	return ocf_req_cache_mode_fast;
}

static int ocf_core_submit_io_fast(struct ocf_request *req, ocf_cache_t cache)
{
	ocf_req_cache_mode_t original_mode, resolved_mode;
	int ret;

	if (req->cache_mode == ocf_req_cache_mode_pt)
		return OCF_FAST_PATH_NO;

	resolved_mode = _ocf_core_req_resolve_fast_mode(cache, req);
	if (resolved_mode == ocf_req_cache_mode_max)
		return OCF_FAST_PATH_NO;

	original_mode = req->cache_mode;
	req->cache_mode = resolved_mode;

	ret = ocf_engine_hndl_fast_req(req);
	if (ret == OCF_FAST_PATH_NO)
		req->cache_mode = original_mode;

	return ret;
}

static void ocf_core_volume_submit_io(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	ocf_core_t core;
	ocf_cache_t cache;
	int ret;

	OCF_CHECK_NULL(io);

	ret = ocf_core_validate_io(io);
	if (ret < 0) {
		ocf_io_end_func(io, ret);
		return;
	}

	core = req->core;
	cache = ocf_core_get_cache(core);

	if (unlikely(ocf_cache_is_standby(cache))) {
		ocf_io_end_func(io, -OCF_ERR_CACHE_STANDBY);
		return;
	}

	req->complete = ocf_req_complete;

	ocf_io_get(io);

	if (unlikely(req->d2c)) {
		ocf_core_update_stats(core, io);
		ocf_d2c_io_fast(req);
		return;
	}

	ret = ocf_req_alloc_map(req);
	if (ret)
		goto err;

	req->part_id = ocf_user_part_class2id(cache, req->io.io_class);

	ocf_resolve_effective_cache_mode(cache, core, req);

	ocf_core_update_stats(core, io);

	/* In case of fastpath prevent completing the requets before updating
	 * sequential cutoff info */
	ocf_req_get(req);

	if (ocf_core_submit_io_fast(req, cache) == OCF_FAST_PATH_YES) {
		ocf_core_seq_cutoff_update(core, req);
		ocf_req_put(req);
		return;
	}

	ocf_req_put(req);
	ocf_req_clear_map(req);
	ocf_core_seq_cutoff_update(core, req);

	ret = ocf_engine_hndl_req(req);
	if (ret) {
		dec_counter_if_req_was_dirty(req);
		goto err;
	}

	return;

err:
	ocf_io_end_func(io, ret);
	ocf_io_put(req);
}

static void ocf_core_volume_submit_flush(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	ocf_cache_t cache;
	int ret;

	OCF_CHECK_NULL(io);

	ret = ocf_core_validate_io(io);
	if (ret < 0) {
		ocf_io_end_func(io, ret);
		return;
	}

	cache = ocf_core_get_cache(req->core);

	if (unlikely(ocf_cache_is_standby(cache))) {
		ocf_io_end_func(io, -OCF_ERR_CACHE_STANDBY);
		return;
	}

	req->complete = ocf_req_complete;

	ocf_io_get(io);

	if (unlikely(req->d2c)) {
		ocf_d2c_flush_fast(req);
		return;
	}

	ocf_engine_hndl_flush_req(req);
}

static void ocf_core_volume_submit_discard(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	ocf_cache_t cache;
	int ret;

	OCF_CHECK_NULL(io);

	if (req->bytes == 0) {
		ocf_io_end_func(io, -OCF_ERR_INVAL);
		return;
	}

	ret = ocf_core_validate_io(io);
	if (ret < 0) {
		ocf_io_end_func(io, ret);
		return;
	}

	cache = ocf_core_get_cache(req->core);

	if (unlikely(ocf_cache_is_standby(cache))) {
		ocf_io_end_func(io, -OCF_ERR_CACHE_STANDBY);
		return;
	}

	req->complete = ocf_req_complete;

	ocf_io_get(io);

	if (unlikely(req->d2c)) {
		ocf_d2c_discard_fast(req);
		return;
	}

	ret = ocf_req_alloc_map_discard(req);
	if (ret) {
		ocf_io_end_func(io, -OCF_ERR_NO_MEM);
		return;
	}

	ocf_engine_hndl_discard_req(req);
}

/* *** VOLUME OPS *** */

static int ocf_core_volume_open(ocf_volume_t volume, void *volume_params)
{
	struct ocf_core_volume *core_volume = ocf_volume_get_priv(volume);
	const struct ocf_volume_uuid *uuid = ocf_volume_get_uuid(volume);
	ocf_core_t core = (ocf_core_t)uuid->data;

	core_volume->core = core;

	return 0;
}

static void ocf_core_volume_close(ocf_volume_t volume)
{
}

static unsigned int ocf_core_volume_get_max_io_size(ocf_volume_t volume)
{
	ocf_core_t core = ocf_volume_to_core(volume);

	return ocf_volume_get_max_io_size(&core->volume);
}

static uint64_t ocf_core_volume_get_byte_length(ocf_volume_t volume)
{
	ocf_core_t core = ocf_volume_to_core(volume);

	return ocf_volume_get_length(&core->volume);
}

const struct ocf_volume_properties ocf_core_volume_properties = {
	.name = "OCF_Core",
	.volume_priv_size = sizeof(struct ocf_core_volume),
	.caps = {
		.atomic_writes = 0,
	},
	.ops = {
		.submit_io = ocf_core_volume_submit_io,
		.submit_flush = ocf_core_volume_submit_flush,
		.submit_discard = ocf_core_volume_submit_discard,
		.submit_metadata = NULL,

		.open = ocf_core_volume_open,
		.close = ocf_core_volume_close,
		.get_max_io_size = ocf_core_volume_get_max_io_size,
		.get_length = ocf_core_volume_get_byte_length,
	},
	.deinit = NULL,
};

static int ocf_core_io_allocator_init(ocf_io_allocator_t allocator,
		const char *name)
{
	return 0;
}

static void ocf_core_io_allocator_deinit(ocf_io_allocator_t allocator)
{
}

static void *ocf_core_io_allocator_new(ocf_io_allocator_t allocator,
		ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir)
{
	ocf_core_t core = ocf_volume_to_core(volume);
	struct ocf_request *req;

	req = ocf_req_new(queue, core, addr, bytes, dir);
	if (!req)
		return NULL;

	req->core = ocf_volume_to_core(volume);

	return req;
}

static void ocf_core_io_allocator_del(ocf_io_allocator_t allocator, void *obj)
{
	struct ocf_request *req = obj;

	ocf_req_put(req);
}

const struct ocf_io_allocator_type ocf_core_io_allocator_type = {
	.ops = {
		.allocator_init = ocf_core_io_allocator_init,
		.allocator_deinit = ocf_core_io_allocator_deinit,
		.allocator_new = ocf_core_io_allocator_new,
		.allocator_del = ocf_core_io_allocator_del,
	},
};

const struct ocf_volume_extended ocf_core_volume_extended = {
	.allocator_type = &ocf_core_io_allocator_type,
};

int ocf_core_volume_type_init(ocf_ctx_t ctx)
{
	return ocf_ctx_register_volume_type_internal(ctx, OCF_VOLUME_TYPE_CORE,
			&ocf_core_volume_properties,
			&ocf_core_volume_extended);
}

int ocf_core_get_info(ocf_core_t core, struct ocf_core_info *info)
{
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!info)
		return -OCF_ERR_INVAL;

	ENV_BUG_ON(env_memset(info, sizeof(*info), 0));

	info->core_size_bytes = ocf_volume_get_length(&core->volume);
	info->core_size = ocf_bytes_2_lines_round_up(cache,
			info->core_size_bytes);
	info->seq_cutoff_threshold = ocf_core_get_seq_cutoff_threshold(core);
	info->seq_cutoff_policy = ocf_core_get_seq_cutoff_policy(core);

	info->flushed = env_atomic_read(&core->flushed);
	info->dirty = env_atomic_read(&core->runtime_meta->dirty_clines);

	info->dirty_for = _calc_dirty_for(
			env_atomic64_read(&core->runtime_meta->dirty_since));

	return 0;
}

void ocf_core_set_priv(ocf_core_t core, void *priv)
{
	OCF_CHECK_NULL(core);
	core->priv = priv;
}

void *ocf_core_get_priv(ocf_core_t core)
{
	OCF_CHECK_NULL(core);
	return core->priv;
}
