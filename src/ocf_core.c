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
#include "ocf_trace_priv.h"

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

	if (!env_bit_test(id, cache->conf_meta->valid_core_bitmap))
		return false;

	return true;
}

int ocf_core_get(ocf_cache_t cache, ocf_core_id_t id, ocf_core_t *core)
{
	OCF_CHECK_NULL(cache);

	if (!ocf_core_is_valid(cache, id))
		return -OCF_ERR_CORE_NOT_AVAIL;

	*core = &cache->core[id];
	return 0;
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

int ocf_core_visit(ocf_cache_t cache, ocf_core_visitor_t visitor, void *cntx,
		bool only_opened)
{
	ocf_core_id_t id;
	int result = 0;

	OCF_CHECK_NULL(cache);

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

static inline struct ocf_core_io *ocf_io_to_core_io(struct ocf_io *io)
{
	return ocf_io_get_priv(io);
}

static inline ocf_core_t ocf_volume_to_core(ocf_volume_t volume)
{
	struct ocf_core_volume *core_volume = ocf_volume_get_priv(volume);

	return core_volume->core;
}

static inline int ocf_io_set_dirty(ocf_cache_t cache,
		struct ocf_core_io *core_io)
{
	core_io->dirty = ocf_refcnt_inc(&cache->dirty);
	return core_io->dirty ? 0 : -EBUSY;
}

static inline void dec_counter_if_req_was_dirty(struct ocf_core_io *core_io,
		ocf_cache_t cache)
{
	if (!core_io->dirty)
		return;

	core_io->dirty = 0;
	ocf_refcnt_dec(&cache->dirty);
}

static inline int ocf_core_validate_io(struct ocf_io *io)
{
	ocf_core_t core;

	if (!io->volume)
		return -EINVAL;

	if (!io->ops)
		return -EINVAL;

	if (io->addr >= ocf_volume_get_length(io->volume))
		return -EINVAL;

	if (io->addr + io->bytes > ocf_volume_get_length(io->volume))
		return -EINVAL;

	if (io->io_class >= OCF_IO_CLASS_MAX)
		return -EINVAL;

	if (io->dir != OCF_READ && io->dir != OCF_WRITE)
		return -EINVAL;

	if (!io->io_queue)
		return -EINVAL;

	if (!io->end)
		return -EINVAL;

	/* Core volume I/O must not be queued on management queue - this would
	 * break I/O accounting code, resulting in use-after-free type of errors
	 * after cache detach, core remove etc. */
	core = ocf_volume_to_core(io->volume);
	if (io->io_queue == ocf_core_get_cache(core)->mngt_queue)
		return -EINVAL;

	return 0;
}

static void ocf_req_complete(struct ocf_request *req, int error)
{
	/* Log trace */
	ocf_trace_io_cmpl(ocf_io_to_core_io(req->io), req->cache);

	/* Complete IO */
	ocf_io_end(req->io, error);

	dec_counter_if_req_was_dirty(ocf_io_to_core_io(req->io), req->cache);

	/* Invalidate OCF IO, it is not valid after completion */
	ocf_io_put(req->io);
	req->io = NULL;
}

void ocf_core_submit_io_mode(struct ocf_io *io, ocf_cache_mode_t cache_mode)
{
	struct ocf_core_io *core_io;
	ocf_req_cache_mode_t req_cache_mode;
	ocf_core_t core;
	ocf_cache_t cache;
	int ret;

	OCF_CHECK_NULL(io);

	ret = ocf_core_validate_io(io);
	if (ret < 0) {
		io->end(io, ret);
		return;
	}

	core_io = ocf_io_to_core_io(io);

	core = ocf_volume_to_core(io->volume);
	cache = ocf_core_get_cache(core);

	ocf_trace_init_io(core_io, cache);

	if (unlikely(!env_bit_test(ocf_cache_state_running,
					&cache->cache_state))) {
		ocf_io_end(io, -EIO);
		return;
	}

	/* TODO: instead of casting ocf_cache_mode_t to ocf_req_cache_mode_t
	   we can resolve IO interface here and get rid of the latter. */
	req_cache_mode = cache_mode;

	if (cache_mode == ocf_cache_mode_none)
		req_cache_mode = ocf_get_effective_cache_mode(cache, core, io);
	if (req_cache_mode == ocf_req_cache_mode_wb &&
			ocf_io_set_dirty(cache, core_io)) {
		req_cache_mode = ocf_req_cache_mode_wt;
	}

	core_io->req = ocf_req_new(io->io_queue, core, io->addr, io->bytes,
			io->dir);
	if (!core_io->req) {
		dec_counter_if_req_was_dirty(core_io, cache);
		io->end(io, -ENOMEM);
		return;
	}

	if (core_io->req->d2c)
		req_cache_mode = ocf_req_cache_mode_d2c;

	core_io->req->part_id = ocf_part_class2id(cache, io->io_class);
	core_io->req->data = core_io->data;
	core_io->req->complete = ocf_req_complete;
	core_io->req->io = io;

	ocf_seq_cutoff_update(core, core_io->req);

	ocf_core_update_stats(core, io);

	if (io->dir == OCF_WRITE)
		ocf_trace_io(core_io, ocf_event_operation_wr, cache);
	else if (io->dir == OCF_READ)
		ocf_trace_io(core_io, ocf_event_operation_rd, cache);

	ocf_io_get(io);
	ret = ocf_engine_hndl_req(core_io->req, req_cache_mode);
	if (ret) {
		dec_counter_if_req_was_dirty(core_io, cache);
		ocf_req_put(core_io->req);
		io->end(io, ret);
	}
}

int ocf_core_submit_io_fast(struct ocf_io *io)
{
	struct ocf_core_io *core_io;
	ocf_req_cache_mode_t req_cache_mode;
	struct ocf_event_io trace_event;
	struct ocf_request *req;
	ocf_core_t core;
	ocf_cache_t cache;
	int fast;
	int ret;

	OCF_CHECK_NULL(io);

	ret = ocf_core_validate_io(io);
	if (ret < 0)
		return ret;

	core_io = ocf_io_to_core_io(io);

	core = ocf_volume_to_core(io->volume);
	cache = ocf_core_get_cache(core);

	if (unlikely(!env_bit_test(ocf_cache_state_running,
			&cache->cache_state))) {
		ocf_io_end(io, -EIO);
		return 0;
	}

	req_cache_mode = ocf_get_effective_cache_mode(cache, core, io);
	if (req_cache_mode == ocf_req_cache_mode_wb &&
			ocf_io_set_dirty(cache, core_io)) {
		req_cache_mode = ocf_req_cache_mode_wt;
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

	core_io->req = ocf_req_new_extended(io->io_queue, core,
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

	req->part_id = ocf_part_class2id(cache, io->io_class);
	req->data = core_io->data;
	req->complete = ocf_req_complete;
	req->io = io;

	ocf_core_update_stats(core, io);

	if (cache->trace.trace_callback) {
		if (io->dir == OCF_WRITE)
			ocf_trace_prep_io_event(&trace_event, core_io, ocf_event_operation_wr);
		else if (io->dir == OCF_READ)
			ocf_trace_prep_io_event(&trace_event, core_io, ocf_event_operation_rd);
	}

	ocf_io_get(io);

	fast = ocf_engine_hndl_fast_req(req, req_cache_mode);
	if (fast != OCF_FAST_PATH_NO) {
		ocf_trace_push(io->io_queue, &trace_event, sizeof(trace_event));
		ocf_seq_cutoff_update(core, req);
		return 0;
	}

	dec_counter_if_req_was_dirty(core_io, cache);

	ocf_io_put(io);
	ocf_req_put(req);
	return -EIO;
}

static void ocf_core_volume_submit_io(struct ocf_io *io)
{
	ocf_core_submit_io_mode(io, ocf_cache_mode_none);
}

static void ocf_core_volume_submit_flush(struct ocf_io *io)
{
	struct ocf_core_io *core_io;
	ocf_core_t core;
	ocf_cache_t cache;
	int ret;

	OCF_CHECK_NULL(io);

	ret = ocf_core_validate_io(io);
	if (ret < 0) {
		ocf_io_end(io, ret);
		return;
	}

	core_io = ocf_io_to_core_io(io);

	core = ocf_volume_to_core(io->volume);
	cache = ocf_core_get_cache(core);

	if (unlikely(!env_bit_test(ocf_cache_state_running,
			&cache->cache_state))) {
		ocf_io_end(io, -EIO);
		return;
	}

	core_io->req = ocf_req_new(io->io_queue, core, io->addr, io->bytes,
			io->dir);
	if (!core_io->req) {
		ocf_io_end(io, -ENOMEM);
		return;
	}

	core_io->req->complete = ocf_req_complete;
	core_io->req->io = io;
	core_io->req->data = core_io->data;

	ocf_trace_io(core_io, ocf_event_operation_flush, cache);
	ocf_io_get(io);
	ocf_engine_hndl_ops_req(core_io->req);
}

static void ocf_core_volume_submit_discard(struct ocf_io *io)
{
	struct ocf_core_io *core_io;
	ocf_core_t core;
	ocf_cache_t cache;
	int ret;

	OCF_CHECK_NULL(io);

	ret = ocf_core_validate_io(io);
	if (ret < 0) {
		ocf_io_end(io, ret);
		return;
	}

	core_io = ocf_io_to_core_io(io);

	core = ocf_volume_to_core(io->volume);
	cache = ocf_core_get_cache(core);

	if (unlikely(!env_bit_test(ocf_cache_state_running,
			&cache->cache_state))) {
		ocf_io_end(io, -EIO);
		return;
	}

	core_io->req = ocf_req_new_discard(io->io_queue, core,
			io->addr, io->bytes, OCF_WRITE);
	if (!core_io->req) {
		ocf_io_end(io, -ENOMEM);
		return;
	}

	core_io->req->complete = ocf_req_complete;
	core_io->req->io = io;
	core_io->req->data = core_io->data;

	ocf_trace_io(core_io, ocf_event_operation_discard, cache);
	ocf_io_get(io);
	ocf_engine_hndl_discard_req(core_io->req);
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


/* *** IO OPS *** */

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

const struct ocf_volume_properties ocf_core_volume_properties = {
	.name = "OCF Core",
	.io_priv_size = sizeof(struct ocf_core_io),
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
	.io_ops = {
		.set_data = ocf_core_io_set_data,
		.get_data = ocf_core_io_get_data,
	},
};

int ocf_core_volume_type_init(ocf_ctx_t ctx)
{
	return ocf_ctx_register_volume_type(ctx, 0,
			&ocf_core_volume_properties);
}

void ocf_core_volume_type_deinit(ocf_ctx_t ctx)
{
	ocf_ctx_unregister_volume_type(ctx, 0);
}
