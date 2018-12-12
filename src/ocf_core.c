/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_priv.h"
#include "ocf_core_priv.h"
#include "ocf_io_priv.h"
#include "metadata/metadata.h"
#include "engine/cache_engine.h"
#include "utils/utils_req.h"
#include "utils/utils_part.h"
#include "utils/utils_device.h"
#include "ocf_request.h"

ocf_cache_t ocf_core_get_cache(ocf_core_t core)
{
	OCF_CHECK_NULL(core);
	return core->obj.cache;
}

ocf_data_obj_t ocf_core_get_data_object(ocf_core_t core)
{
	OCF_CHECK_NULL(core);
	return &core->obj;
}

ocf_core_id_t ocf_core_get_id(ocf_core_t core)
{
	struct ocf_cache *cache;
	ocf_core_id_t core_id;

	OCF_CHECK_NULL(core);

	cache = core->obj.cache;
	core_id = core - cache->core_obj;

	return core_id;
}

int ocf_core_set_name(ocf_core_t core, const char *src, size_t src_size)
{
	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(src);

	return env_strncpy(core->name, sizeof(core->name), src, src_size);
}

const char *ocf_core_get_name(ocf_core_t core)
{
	OCF_CHECK_NULL(core);

	return core->name;
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

	if (id > OCF_CORE_ID_MAX || id < OCF_CORE_ID_MIN)
		return false;

	if (!env_bit_test(id, cache->conf_meta->valid_object_bitmap))
		return false;

	return true;
}

int ocf_core_get(ocf_cache_t cache, ocf_core_id_t id, ocf_core_t *core)
{
	OCF_CHECK_NULL(cache);

	if (!ocf_core_is_valid(cache, id))
		return -OCF_ERR_CORE_NOT_AVAIL;

	*core = &cache->core_obj[id];
	return 0;
}

int ocf_core_set_uuid(ocf_core_t core, const struct ocf_data_obj_uuid *uuid)
{
	struct ocf_cache *cache;
	struct ocf_data_obj_uuid *current_uuid;
	int result;
	int diff;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(uuid);
	OCF_CHECK_NULL(uuid->data);

	cache = core->obj.cache;
	current_uuid = &ocf_core_get_data_object(core)->uuid;

	result = env_memcmp(current_uuid->data, current_uuid->size,
			uuid->data, uuid->size, &diff);
	if (result)
		return result;

	if (!diff) {
		/* UUIDs are identical */
		return 0;
	}

	result = ocf_uuid_core_set(cache, core, uuid);
	if (result)
		return result;

	result = ocf_metadata_flush_superblock(cache);
	if (result) {
		result = -OCF_ERR_WRITE_CACHE;
	}

	return result;
}

static inline void inc_dirty_req_counter(struct ocf_core_io *core_io,
		ocf_cache_t cache)
{
	core_io->dirty = 1;
	env_atomic_inc(&cache->pending_dirty_requests);
}

static inline void dec_counter_if_req_was_dirty(struct ocf_core_io *core_io,
		ocf_cache_t cache)
{
	int pending_dirty_req_count;

	if (!core_io->dirty)
		return;

	pending_dirty_req_count =
		env_atomic_dec_return(&cache->pending_dirty_requests);

	ENV_BUG_ON(pending_dirty_req_count < 0);

	core_io->dirty = 0;

	if (!pending_dirty_req_count)
		env_waitqueue_wake_up(&cache->pending_dirty_wq);
}

/* *** CORE IO *** */

static inline struct ocf_core_io *ocf_io_to_core_io(struct ocf_io *io)
{
	return container_of(io, struct ocf_core_io, base);
}

static void ocf_core_io_get(struct ocf_io *io)
{
	struct ocf_core_io *core_io;
	int value;

	OCF_CHECK_NULL(io);

	core_io = ocf_io_to_core_io(io);
	value = env_atomic_inc_return(&core_io->ref_counter);

	ENV_BUG_ON(value < 1);
}

static void ocf_core_io_put(struct ocf_io *io)
{
	struct ocf_core_io *core_io;
	ocf_cache_t cache;
	int value;

	OCF_CHECK_NULL(io);

	core_io = ocf_io_to_core_io(io);
	value = env_atomic_dec_return(&core_io->ref_counter);

	ENV_BUG_ON(value < 0);

	if (value)
		return;

	cache = ocf_core_get_cache(core_io->core);

	core_io->data = NULL;
	env_allocator_del(cache->owner->resources.core_io_allocator, core_io);
}

static int ocf_core_io_set_data(struct ocf_io *io,
		ctx_data_t *data, uint32_t offset)
{
	struct ocf_core_io *core_io;

	OCF_CHECK_NULL(io);

	if (!data || offset)
		return -EINVAL;

	core_io = ocf_io_to_core_io(io);
	core_io->data = data;

	return 0;
}

static ctx_data_t *ocf_core_io_get_data(struct ocf_io *io)
{
	struct ocf_core_io *core_io;

	OCF_CHECK_NULL(io);

	core_io = ocf_io_to_core_io(io);
	return core_io->data;
}

uint32_t ocf_core_get_seq_cutoff_threshold(ocf_core_t core)
{
	uint32_t core_id = ocf_core_get_id(core);
	ocf_cache_t cache = ocf_core_get_cache(core);

	return cache->core_conf_meta[core_id].seq_cutoff_threshold;
}

ocf_seq_cutoff_policy ocf_core_get_seq_cutoff_policy(ocf_core_t core)
{
	uint32_t core_id = ocf_core_get_id(core);
	ocf_cache_t cache = ocf_core_get_cache(core);

	return cache->core_conf_meta[core_id].seq_cutoff_policy;
}

const struct ocf_io_ops ocf_core_io_ops = {
	.set_data = ocf_core_io_set_data,
	.get_data = ocf_core_io_get_data,
	.get = ocf_core_io_get,
	.put = ocf_core_io_put,
};

int ocf_core_set_user_metadata_raw(ocf_core_t core, void *data, size_t size)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	uint32_t core_id = ocf_core_get_id(core);

	if (size > OCF_CORE_USER_DATA_SIZE)
		return -EINVAL;

	env_memcpy(cache->core_conf_meta[core_id].user_data,
			OCF_CORE_USER_DATA_SIZE, data, size);

	return 0;
}

int ocf_core_set_user_metadata(ocf_core_t core, void *data, size_t size)
{
	ocf_cache_t cache;
	int ret;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(data);

	cache = ocf_core_get_cache(core);

	ret = ocf_core_set_user_metadata_raw(core, data, size);
	if (ret)
		return ret;

	ret = ocf_metadata_flush_superblock(cache);
	if (ret)
		return -OCF_ERR_WRITE_CACHE;

	return 0;
}

int ocf_core_get_user_metadata(ocf_core_t core, void *data, size_t size)
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

/* *** OCF API *** */

static inline int ocf_validate_io(struct ocf_core_io *core_io)
{
	ocf_cache_t cache = ocf_core_get_cache(core_io->core);
	struct ocf_io *io = &core_io->base;

	if (!io->obj)
		return -EINVAL;

	if (!io->ops)
		return -EINVAL;

	if (io->addr >= ocf_data_obj_get_length(io->obj))
		return -EINVAL;

	if (io->addr + io->bytes > ocf_data_obj_get_length(io->obj))
		return -EINVAL;

	if (io->class >= OCF_IO_CLASS_MAX)
		return -EINVAL;

	if (io->dir != OCF_READ && io->dir != OCF_WRITE)
		return -EINVAL;

	if (io->io_queue >= cache->io_queues_no)
		return -EINVAL;

	if (!io->end)
		return -EINVAL;

	return 0;
}

static void ocf_req_complete(struct ocf_request *req, int error)
{
	/* Complete IO */
	ocf_io_end(req->io, error);

	dec_counter_if_req_was_dirty(ocf_io_to_core_io(req->io), req->cache);

	/* Invalidate OCF IO, it is not valid after completion */
	ocf_core_io_put(req->io);
	req->io = NULL;
}

struct ocf_io *ocf_new_io(ocf_core_t core)
{
	ocf_cache_t cache;
	struct ocf_core_io *core_io;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);
	if (!cache)
		return NULL;

	core_io = env_allocator_new(
			cache->owner->resources.core_io_allocator);
	if (!core_io)
		return NULL;

	core_io->base.obj = ocf_core_get_data_object(core);
	core_io->base.ops = &ocf_core_io_ops;
	core_io->core = core;

	env_atomic_set(&core_io->ref_counter, 1);

	return &core_io->base;
}

int ocf_submit_io_mode(struct ocf_io *io, ocf_cache_mode_t cache_mode)
{
	struct ocf_core_io *core_io;
	ocf_req_cache_mode_t req_cache_mode;
	ocf_core_t core;
	ocf_cache_t cache;
	int ret;

	if (!io)
		return -EINVAL;

	core_io = ocf_io_to_core_io(io);

	ret = ocf_validate_io(core_io);
	if (ret < 0)
		return ret;

	core = core_io->core;
	cache = ocf_core_get_cache(core);

	if (unlikely(!env_bit_test(ocf_cache_state_running,
					&cache->cache_state))) {
		ocf_io_end(io, -EIO);
		return 0;
	}

	/* TODO: instead of casting ocf_cache_mode_t to ocf_req_cache_mode_t
	   we can resolve IO interface here and get rid of the latter. */
	req_cache_mode = cache_mode;

	if (cache_mode == ocf_cache_mode_none)
		req_cache_mode = ocf_get_effective_cache_mode(cache, core, io);

	if (req_cache_mode == ocf_req_cache_mode_wb) {
		inc_dirty_req_counter(core_io, cache);

		//Double cache mode check prevents sending WB request
		//while flushing is performed.
		req_cache_mode = ocf_get_effective_cache_mode(cache, core, io);
		if (req_cache_mode != ocf_req_cache_mode_wb)
			dec_counter_if_req_was_dirty(core_io, cache);
	}

	if (cache->conf_meta->valid_parts_no <= 1)
		io->class = 0;

	core_io->req = ocf_req_new(cache, ocf_core_get_id(core),
			io->addr, io->bytes, io->dir);
	if (!core_io->req) {
		dec_counter_if_req_was_dirty(core_io, cache);
		io->end(io, -ENOMEM);
		return 0;
	}

	if (core_io->req->d2c)
		req_cache_mode = ocf_req_cache_mode_d2c;

	core_io->req->io_queue = io->io_queue;
	core_io->req->part_id = ocf_part_class2id(cache, io->class);
	core_io->req->data = core_io->data;
	core_io->req->complete = ocf_req_complete;
	core_io->req->io = io;

	ocf_seq_cutoff_update(core, core_io->req);

	ocf_core_update_stats(core, io);

	ocf_core_io_get(io);
	ret = ocf_engine_hndl_req(core_io->req, req_cache_mode);
	if (ret) {
		dec_counter_if_req_was_dirty(core_io, cache);
		ocf_req_put(core_io->req);
		io->end(io, ret);
	}

	return 0;
}

int ocf_submit_io_fast(struct ocf_io *io)
{
	struct ocf_core_io *core_io;
	ocf_req_cache_mode_t req_cache_mode;
	struct ocf_request *req;
	ocf_core_t core;
	ocf_cache_t cache;
	int fast;
	int ret;

	if (!io)
		return -EINVAL;

	core_io = ocf_io_to_core_io(io);

	ret = ocf_validate_io(core_io);
	if (ret < 0)
		return ret;

	core = core_io->core;
	cache = ocf_core_get_cache(core);

	if (unlikely(!env_bit_test(ocf_cache_state_running,
			&cache->cache_state))) {
		ocf_io_end(io, -EIO);
		return 0;
	}

	req_cache_mode = ocf_get_effective_cache_mode(cache, core, io);
	if (req_cache_mode == ocf_req_cache_mode_wb) {
		inc_dirty_req_counter(core_io, cache);

		//Double cache mode check prevents sending WB request
		//while flushing is performed.
		req_cache_mode = ocf_get_effective_cache_mode(cache, core, io);
		if (req_cache_mode != ocf_req_cache_mode_wb)
			dec_counter_if_req_was_dirty(core_io, cache);
	}

	switch (req_cache_mode) {
	case ocf_req_cache_mode_pt:
		return -EIO;
	case ocf_req_cache_mode_wb:
		req_cache_mode = ocf_req_cache_mode_fast;
		break;
	default:
		if (cache->use_submit_io_fast)
			break;
		if (io->dir == OCF_WRITE)
			return -EIO;

		req_cache_mode = ocf_req_cache_mode_fast;
	}

	if (cache->conf_meta->valid_parts_no <= 1)
		io->class = 0;

	core_io->req = ocf_req_new_extended(cache, ocf_core_get_id(core),
			io->addr, io->bytes, io->dir);
	// We need additional pointer to req in case completion arrives before
	// we leave this function and core_io is freed
	req = core_io->req;

	if (!req) {
		dec_counter_if_req_was_dirty(core_io, cache);
		io->end(io, -ENOMEM);
		return 0;
	}
	if (req->d2c) {
		dec_counter_if_req_was_dirty(core_io, cache);
		ocf_req_put(req);
		return -EIO;
	}

	req->io_queue = io->io_queue;
	req->part_id = ocf_part_class2id(cache, io->class);
	req->data = core_io->data;
	req->complete = ocf_req_complete;
	req->io = io;

	ocf_core_update_stats(core, io);
	ocf_core_io_get(io);

	fast = ocf_engine_hndl_fast_req(req, req_cache_mode);
	if (fast != OCF_FAST_PATH_NO) {
		ocf_seq_cutoff_update(core, req);
		return 0;
	}

	dec_counter_if_req_was_dirty(core_io, cache);

	ocf_core_io_put(io);
	ocf_req_put(req);
	return -EIO;
}

int ocf_submit_flush(struct ocf_io *io)
{
	struct ocf_core_io *core_io;
	ocf_core_t core;
	ocf_cache_t cache;
	int ret;

	if (!io)
		return -EINVAL;

	core_io = ocf_io_to_core_io(io);

	ret = ocf_validate_io(core_io);
	if (ret < 0)
		return ret;

	core = core_io->core;
	cache = ocf_core_get_cache(core);

	if (unlikely(!env_bit_test(ocf_cache_state_running,
			&cache->cache_state))) {
		ocf_io_end(io, -EIO);
		return 0;
	}

	core_io->req = ocf_req_new(cache, ocf_core_get_id(core),
			io->addr, io->bytes, io->dir);
	if (!core_io->req) {
		ocf_io_end(io, -ENOMEM);
		return 0;
	}

	core_io->req->io_queue = io->io_queue;
	core_io->req->complete = ocf_req_complete;
	core_io->req->io = io;
	core_io->req->data = core_io->data;

	ocf_core_io_get(io);
	ocf_engine_hndl_ops_req(core_io->req);

	return 0;
}

int ocf_submit_discard(struct ocf_io *io)
{
	struct ocf_core_io *core_io;
	ocf_core_t core;
	ocf_cache_t cache;
	int ret;

	if (!io)
		return -EINVAL;

	core_io = ocf_io_to_core_io(io);

	ret = ocf_validate_io(core_io);
	if (ret < 0)
		return ret;

	core = core_io->core;
	cache = ocf_core_get_cache(core);

	if (unlikely(!env_bit_test(ocf_cache_state_running,
			&cache->cache_state))) {
		ocf_io_end(io, -EIO);
		return 0;
	}

	core_io->req = ocf_req_new_discard(cache, ocf_core_get_id(core),
			io->addr, io->bytes, OCF_WRITE);
	if (!core_io->req) {
		ocf_io_end(io, -ENOMEM);
		return 0;
	}

	core_io->req->io_queue = io->io_queue;
	core_io->req->complete = ocf_req_complete;
	core_io->req->io = io;
	core_io->req->data = core_io->data;

	ocf_core_io_get(io);
	ocf_engine_hndl_discard_req(core_io->req);

	return 0;
}

int ocf_core_visit(ocf_cache_t cache, ocf_core_visitor_t visitor, void *cntx,
		bool only_opened)
{
	ocf_core_id_t id;
	int result = 0;

	OCF_CHECK_NULL(cache);

	if (!visitor)
		return -OCF_ERR_INVAL;

	for (id = 0; id < OCF_CORE_MAX; id++) {
		if (!env_bit_test(id, cache->conf_meta->valid_object_bitmap))
			continue;

		if (only_opened && !cache->core_obj[id].opened)
			continue;

		result = visitor(&cache->core_obj[id], cntx);
		if (result)
			break;
	}

	return result;
}

