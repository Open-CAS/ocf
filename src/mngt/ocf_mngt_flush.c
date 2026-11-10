/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_env_refcnt.h"
#include "ocf_mngt_flush_priv.h"
#include "ocf_mngt_common.h"
#include "ocf_mngt_flush_priv.h"
#include "../ocf_priv.h"
#include "../metadata/metadata.h"
#include "../cleaning/cleaning.h"
#include "../engine/cache_engine.h"
#include "../engine/engine_common.h"
#include "../utils/utils_cleaner.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_user_part.h"
#include "../utils/utils_pipeline.h"
#include "../ocf_request.h"
#include "../ocf_def_priv.h"
#include "../concurrency/ocf_metadata_concurrency.h"

struct ocf_mngt_cache_flush_context;
typedef void (*ocf_flush_complete_t)(struct ocf_mngt_cache_flush_context *, int);

struct flush_sweep {
	struct ocf_mngt_cache_flush_context *context;
	ocf_cache_t cache;
	/* next hash bucket to examine and the end of the slice */
	ocf_cache_line_t bucket;
	ocf_cache_line_t end;
	/* portion being cleaned */
	struct flush_data *data;
	uint32_t count;
	struct ocf_cleaner_attribs attribs;
	struct ocf_request *req;
	/* portion size, adapted to the time the last portion took */
	uint64_t flush_portion;
	uint64_t ticks1;
	uint64_t ticks2;
};

struct flush_sweeps_context {
	/* range of cache lines to flush */
	ocf_cache_line_t begin;
	ocf_cache_line_t end;
	/* slices of the hash table, swept concurrently */
	struct flush_sweep *sweeps;
	uint32_t num;
	/* shared error for all concurrent sweeps */
	env_atomic error;
	/* number of sweeps in progress, plus one while starting them */
	env_atomic count;
	/* first sweep to notice interrupt sets this to 1 */
	env_atomic interrupt_seen;
	/* completion to be called after all sweeps are done */
	ocf_flush_complete_t complete;
};

/* common struct for cache/core flush/purge pipeline priv */
struct ocf_mngt_cache_flush_context {
	/* pipeline for flush / purge */
	ocf_pipeline_t pipeline;
	/* target cache */
	ocf_cache_t cache;
	/* target core */
	ocf_core_t core;

	/* Flush only range of cache lines */
	ocf_cache_line_t begin;
	ocf_cache_line_t end;

	struct {
		bool lock : 1;
		bool dirty_freeze : 1;
		bool metadata_freeze : 1;
	} flags;

	/* management operation identifier */
	enum {
		flush_cache = 0,
		flush_core,
		purge_cache,
		purge_core
	} op;

	/* ocf management entry point completion */
	union {
		ocf_mngt_cache_flush_end_t flush_cache;
		ocf_mngt_core_flush_end_t flush_core;
		ocf_mngt_cache_purge_end_t purge_cache;
		ocf_mngt_core_purge_end_t purge_core;
	} cmpl;

	/* completion pivate data */
	void *priv;

	/* purge parameters */
	struct {
		uint64_t end_byte;
		uint64_t core_id;
	} purge;

	/* context for the flush sweeps */
	struct flush_sweeps_context fsc;
};

static void _ocf_mngt_begin_flush(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_flush_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	/* FIXME: need mechanism for async waiting for outstanding flushes to
	 * finish */
	result = env_mutex_trylock(&cache->flush_mutex);
	if (result)
		OCF_PL_FINISH_RET(pipeline, -OCF_ERR_FLUSH_IN_PROGRESS);
	context->flags.lock = true;

	env_refcnt_freeze(&cache->refcnt.dirty);
	context->flags.dirty_freeze = true;

	ocf_pipeline_continue_on_zero_refcnt(context->pipeline,
			&cache->refcnt.dirty);
}

static void _ocf_mngt_begin_cache_lines_invalidate(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_flush_context *context = priv;
	struct env_refcnt *refcnt = &context->cache->refcnt.metadata;

	env_refcnt_freeze(refcnt);
	context->flags.metadata_freeze = true;
	ocf_pipeline_continue_on_zero_refcnt(context->pipeline, refcnt);
}

bool ocf_mngt_core_is_dirty(ocf_core_t core)
{
	ocf_cache_t cache;

	cache = ocf_core_get_cache(core);
	if (ocf_cache_is_standby(cache))
		return false;

	return !!env_atomic_read(&core->runtime_meta->dirty_clines);
}

bool ocf_mngt_cache_is_dirty(ocf_cache_t cache)
{
	ocf_core_t core;
	ocf_core_id_t core_id;

	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return false;

	for_each_core(cache, core, core_id) {
		if (ocf_mngt_core_is_dirty(core))
			return true;
	}

	return false;
}

void ocf_mngt_cache_set_no_dirty(ocf_cache_t cache, bool no_dirty)
{
	OCF_CHECK_NULL(cache);

	if (no_dirty == cache->no_dirty)
		return;

	cache->no_dirty = no_dirty;

	if (no_dirty)
		env_refcnt_freeze(&cache->refcnt.dirty);
	else
		env_refcnt_unfreeze(&cache->refcnt.dirty);
}

/************************FLUSH CORE CODE**************************************/

#define OCF_MNG_FLUSH_MIN (4*MiB / ocf_line_size(cache))
#define OCF_MNG_FLUSH_MAX (100*MiB / ocf_line_size(cache))

#define OCF_MNG_FLUSH_SLICES 16

/* Hash buckets examined between reschedules */
#define OCF_MNG_FLUSH_RESCHED_BUCKETS 131072

static bool _ocf_mngt_flush_target(struct ocf_mngt_cache_flush_context *context,
		ocf_core_id_t core_id)
{
	if (context->core)
		return core_id == ocf_core_get_id(context->core);

	return core_id < OCF_CORE_NUM;
}

static uint32_t _ocf_mngt_flush_target_dirty(
		struct ocf_mngt_cache_flush_context *context)
{
	ocf_cache_t cache = context->cache;
	ocf_core_t core;
	ocf_core_id_t core_id;
	uint32_t dirty = 0;

	if (context->core) {
		return env_atomic_read(
				&context->core->runtime_meta->dirty_clines);
	}

	for_each_core(cache, core, core_id)
		dirty += env_atomic_read(&core->runtime_meta->dirty_clines);

	return dirty;
}

static void _ocf_mngt_flush_collect(struct flush_sweep *sweep, uint32_t max)
{
	struct ocf_mngt_cache_flush_context *context = sweep->context;
	struct flush_sweeps_context *fsc = &context->fsc;
	ocf_cache_t cache = sweep->cache;
	ocf_cache_line_t terminator =
			ocf_metadata_terminator_line(&cache->metadata);
	ocf_cache_line_t line, next;
	ocf_core_id_t core_id;
	uint64_t core_line;
	uint32_t scanned = 0, bucket_start;
	unsigned lock_idx;
	bool bucket_done;

	sweep->count = 0;

	while (sweep->bucket < sweep->end && sweep->count < max) {
		bucket_start = sweep->count;

		lock_idx = ocf_metadata_concurrency_next_idx(cache->mngt_queue);
		ocf_hb_id_prot_lock_rd(&cache->metadata_lock, lock_idx,
				sweep->bucket);

		bucket_done = true;
		next = ocf_metadata_get_hash(cache, sweep->bucket);
		while (next != terminator) {
			line = next;
			next = ocf_metadata_get_collision_next(cache, line);

			ocf_metadata_get_core_info(cache, line, &core_id,
					&core_line);

			if (line < fsc->begin || line >= fsc->end)
				continue;
			if (!_ocf_mngt_flush_target(context, core_id))
				continue;
			if (!metadata_test_valid_any(cache, line))
				continue;
			if (!metadata_test_dirty(cache, line))
				continue;
			if (sweep->count == max) {
				bucket_done = false;
				break;
			}
			sweep->data[sweep->count].cache_line = line;
			sweep->data[sweep->count].core_line = core_line;
			sweep->data[sweep->count].core_id = core_id;
			sweep->count++;
		}

		ocf_hb_id_prot_unlock_rd(&cache->metadata_lock, lock_idx,
				sweep->bucket);

		if (!bucket_done) {
			if (bucket_start > 0)
				sweep->count = bucket_start;
			break;
		}

		sweep->bucket++;

		if (++scanned % OCF_MNG_FLUSH_RESCHED_BUCKETS == 0)
			env_cond_resched();
	}
}

static void _ocf_mngt_flush_account(struct flush_sweep *sweep)
{
	ocf_cache_t cache = sweep->cache;
	uint32_t i, run = 0;

	for (i = 0; i < sweep->count; i++) {
		run++;
		if (i + 1 < sweep->count && sweep->data[i + 1].core_id ==
				sweep->data[i].core_id) {
			continue;
		}

		env_atomic_add(run, &ocf_cache_get_core(cache,
					sweep->data[i].core_id)->flushed);
		run = 0;
	}
}

static void _ocf_mngt_flush_sweep_complete(struct flush_sweep *sweep);

static void _ocf_mngt_flush_portion_end(void *private_data, int error)
{
	struct flush_sweep *sweep = private_data;
	struct ocf_mngt_cache_flush_context *context = sweep->context;
	struct flush_sweeps_context *fsc = &context->fsc;
	ocf_cache_t cache = context->cache;
	bool first_interrupt;

	_ocf_mngt_flush_account(sweep);

	sweep->ticks2 = env_get_tick_count();

	env_atomic_cmpxchg(&fsc->error, 0, error);

	if (cache->flushing_interrupted) {
		first_interrupt = !env_atomic_cmpxchg(
				&fsc->interrupt_seen, 0, 1);
		if (first_interrupt) {
			ocf_cache_log(cache, log_info,
					"Flushing interrupted by user\n");
			env_atomic_cmpxchg(&fsc->error, 0,
					-OCF_ERR_FLUSHING_INTERRUPTED);
		}
	}

	if (env_atomic_read(&fsc->error)) {
		_ocf_mngt_flush_sweep_complete(sweep);
		return;
	}

	ocf_queue_push_req(sweep->req, 0);
}

static int _ocf_mngt_flush_sweep_step(struct ocf_request *req)
{
	struct flush_sweep *sweep = req->priv;
	ocf_cache_t cache = sweep->cache;
	uint64_t flush_portion_div;

	/* Nothing left to flush - skip the rest of the slice */
	if (_ocf_mngt_flush_target_dirty(sweep->context) == 0)
		sweep->bucket = sweep->end;

	flush_portion_div = env_ticks_to_msecs(sweep->ticks2 - sweep->ticks1);
	if (unlikely(!flush_portion_div))
		flush_portion_div = 1;

	sweep->flush_portion = sweep->flush_portion * 1000 / flush_portion_div;
	sweep->flush_portion &= ~0x3ffULL;

	/*
	 * regardless those calculations, limit flush portion to be
	 * between OCF_MNG_FLUSH_MIN and OCF_MNG_FLUSH_MAX
	 */
	sweep->flush_portion = OCF_MIN(sweep->flush_portion, OCF_MNG_FLUSH_MAX);
	sweep->flush_portion = OCF_MAX(sweep->flush_portion, OCF_MNG_FLUSH_MIN);

	_ocf_mngt_flush_collect(sweep, sweep->flush_portion);

	if (sweep->count == 0) {
		_ocf_mngt_flush_sweep_complete(sweep);
		return 0;
	}

	/* The consecutive ranges are interleaved, we need to sort first */
	ocf_cleaner_sort_flush_data(sweep->data, sweep->count);

	sweep->ticks1 = env_get_tick_count();

	ocf_metadata_start_exclusive_access(&cache->metadata_lock);
	ocf_cleaner_do_flush_data_async(cache, sweep->data, sweep->count,
			&sweep->attribs);
	ocf_metadata_end_exclusive_access(&cache->metadata_lock);

	return 0;
}

static void _ocf_mngt_flush_sweeps_free(struct flush_sweeps_context *fsc)
{
	uint32_t i;

	for (i = 0; i < fsc->num; i++) {
		if (fsc->sweeps[i].req)
			ocf_req_put(fsc->sweeps[i].req);
		env_vfree(fsc->sweeps[i].data);
	}
	env_vfree(fsc->sweeps);
	fsc->sweeps = NULL;
	fsc->num = 0;
}

static void _ocf_mngt_flush_sweeps_put(
		struct ocf_mngt_cache_flush_context *context)
{
	struct flush_sweeps_context *fsc = &context->fsc;

	if (env_atomic_dec_return(&fsc->count))
		return;

	_ocf_mngt_flush_sweeps_free(fsc);

	fsc->complete(context, env_atomic_read(&fsc->error));
}

static void _ocf_mngt_flush_sweep_complete(struct flush_sweep *sweep)
{
	_ocf_mngt_flush_sweeps_put(sweep->context);
}

static uint32_t _ocf_mngt_flush_dirty_cores(
		struct ocf_mngt_cache_flush_context *context)
{
	ocf_cache_t cache = context->cache;
	ocf_core_t core;
	ocf_core_id_t core_id;
	uint32_t num = 0;

	if (context->core)
		return 1;

	for_each_core(cache, core, core_id) {
		if (env_atomic_read(&core->runtime_meta->dirty_clines))
			num++;
	}

	return num;
}

static void _ocf_mngt_flush_sweeps(
		struct ocf_mngt_cache_flush_context *context,
		ocf_cache_line_t begin, ocf_cache_line_t end,
		ocf_flush_complete_t complete)
{
	struct flush_sweeps_context *fsc = &context->fsc;
	ocf_cache_t cache = context->cache;
	struct flush_sweep *sweep;
	uint32_t i, num;
	uint64_t buckets = ocf_metadata_hash_entries(&cache->metadata);

	end = OCF_MIN(ocf_metadata_line_count(&cache->metadata), end);

	if (begin > end) {
		complete(context, -OCF_ERR_INVAL);
		return;
	}

	if (begin == end) {
		ocf_cache_log(cache, log_warn, "Flush with 0 length\n");
		complete(context, 0);
		return;
	}

	if (_ocf_mngt_flush_target_dirty(context) == 0) {
		complete(context, 0);
		return;
	}

	fsc->begin = begin;
	fsc->end = end;

	num = _ocf_mngt_flush_dirty_cores(context);
	num = OCF_MIN(num, OCF_MNG_FLUSH_SLICES);
	num = OCF_MIN(num, buckets);
	num = OCF_MAX(num, 1);

	fsc->sweeps = env_vzalloc(sizeof(*fsc->sweeps) * num);
	if (!fsc->sweeps)
		goto err_nomem;
	fsc->num = num;

	for (i = 0; i < num; i++) {
		sweep = &fsc->sweeps[i];

		sweep->data = env_vmalloc(sizeof(*sweep->data) *
				OCF_MNG_FLUSH_MAX);
		if (!sweep->data)
			goto err_free;

		sweep->req = ocf_req_new_mngt(cache, cache->mngt_queue);
		if (!sweep->req)
			goto err_free;

		sweep->req->info.internal = true;
		sweep->req->engine_handler = _ocf_mngt_flush_sweep_step;
		sweep->req->priv = sweep;

		sweep->context = context;
		sweep->cache = cache;
		sweep->bucket = buckets * i / num;
		sweep->end = buckets * (i + 1) / num;

		sweep->attribs.lock_cacheline = true;
		sweep->attribs.cmpl_context = sweep;
		sweep->attribs.cmpl_fn = _ocf_mngt_flush_portion_end;
		sweep->attribs.io_queue = cache->mngt_queue;

		sweep->flush_portion = OCF_MNG_FLUSH_MIN;
		sweep->ticks1 = 0;
		sweep->ticks2 = UINT_MAX;
	}

	env_atomic_set(&fsc->error, 0);
	env_atomic_set(&fsc->interrupt_seen, 0);
	env_atomic_set(&fsc->count, num + 1);
	fsc->complete = complete;

	for (i = 0; i < num; i++)
		ocf_queue_push_req(fsc->sweeps[i].req, OCF_QUEUE_ALLOW_SYNC);

	_ocf_mngt_flush_sweeps_put(context);
	return;

err_free:
	_ocf_mngt_flush_sweeps_free(fsc);
err_nomem:
	if (context->core) {
		ocf_core_log(context->core, log_err,
				"Flushing operation aborted, no memory\n");
	} else {
		ocf_cache_log(cache, log_err,
				"Flushing operation aborted, no memory\n");
	}
	complete(context, -OCF_ERR_NO_MEM);
}

static void _ocf_mngt_flush_core(
	struct ocf_mngt_cache_flush_context *context,
	ocf_flush_complete_t complete)
{
	_ocf_mngt_flush_sweeps(context, 0,
			ocf_metadata_line_count(&context->cache->metadata),
			complete);
}

static void _ocf_mngt_flush_all_cores(
	struct ocf_mngt_cache_flush_context *context,
	ocf_flush_complete_t complete)
{
	ocf_cache_t cache = context->cache;

	if (context->op == flush_cache)
		ocf_cache_log(cache, log_info, "Flushing cache\n");
	else if (context->op == purge_cache)
		ocf_cache_log(cache, log_info, "Purging cache\n");

	env_atomic_set(&cache->flush_in_progress, 1);

	_ocf_mngt_flush_sweeps(context, context->begin, context->end, complete);
}

static void _ocf_mngt_flush_all_cores_complete(
		struct ocf_mngt_cache_flush_context *context, int error)
{
	ocf_cache_t cache = context->cache;
	uint32_t i, j;

	env_atomic_set(&cache->flush_in_progress, 0);

	for (i = 0, j = 0; i < OCF_CORE_NUM; i++) {
		if (!env_bit_test(i, cache->conf_meta->valid_core_bitmap))
			continue;

		env_atomic_set(&cache->core[i].flushed, 0);

		if (++j == cache->conf_meta->core_count)
			break;
	}

	if (error)
		OCF_PL_FINISH_RET(context->pipeline, error);

	if (context->op == flush_cache)
		ocf_cache_log(cache, log_info, "Flushing cache completed\n");

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_cache_flush(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_flush_context *context = priv;

	context->cache->flushing_interrupted = 0;
	_ocf_mngt_flush_all_cores(context, _ocf_mngt_flush_all_cores_complete);
}

static void _ocf_mngt_flush_finish(ocf_pipeline_t pipeline, void *priv,
		int error)

{
	struct ocf_mngt_cache_flush_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;

	if (context->flags.metadata_freeze)
		env_refcnt_unfreeze(&cache->refcnt.metadata);

	if (context->flags.dirty_freeze)
		env_refcnt_unfreeze(&cache->refcnt.dirty);

	if (context->flags.lock)
		env_mutex_unlock(&cache->flush_mutex);

	switch (context->op) {
	case flush_cache:
		context->cmpl.flush_cache(cache, context->priv, error);
		break;
	case flush_core:
		context->cmpl.flush_core(core, context->priv, error);
		break;
	case purge_cache:
		context->cmpl.purge_cache(cache, context->priv, error);
		break;
	case purge_core:
		context->cmpl.purge_core(core, context->priv, error);
		break;
	default:
		ENV_BUG();
	}

	ocf_pipeline_destroy(pipeline);
}

static struct ocf_pipeline_properties _ocf_mngt_cache_flush_pipeline_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_flush_context),
	.finish = _ocf_mngt_flush_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_begin_flush),
		OCF_PL_STEP(_ocf_mngt_cache_flush),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_cache_flush(ocf_cache_t cache,
		ocf_mngt_cache_flush_end_t cmpl, void *priv)
{
	ocf_pipeline_t pipeline;
	struct ocf_mngt_cache_flush_context *context;
	int result = 0;

	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache)) {
		ocf_cache_log(cache, log_err, "Cannot flush cache - cache is standby\n");
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_STANDBY);
	}

	if (!ocf_cache_is_device_attached(cache)) {
		ocf_cache_log(cache, log_err, "Cannot flush cache - "
				"cache device is detached\n");
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_DETACHED);
	}

	if (ocf_cache_is_incomplete(cache)) {
		ocf_cache_log(cache, log_err, "Cannot flush cache - "
				"cache is in incomplete state\n");
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_IN_INCOMPLETE_STATE);
	}

	if (!cache->mngt_queue) {
		ocf_cache_log(cache, log_err,
				"Cannot flush cache - no flush queue set\n");
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);
	}

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_cache_flush_pipeline_properties);
	if (result)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_NO_MEM);

	context = ocf_pipeline_get_priv(pipeline);

	context->pipeline = pipeline;
	context->cmpl.flush_cache = cmpl;
	context->priv = priv;
	context->cache = cache;
	context->op = flush_cache;
	context->begin = 0;
	context->end = ocf_metadata_line_count(&cache->metadata);

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_flush_core_complete(
		struct ocf_mngt_cache_flush_context *context, int error)
{
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;

	env_atomic_set(&core->flushed, 0);

	if (error)
		OCF_PL_FINISH_RET(context->pipeline, error);

	if (context->op == flush_core)
		ocf_cache_log(cache, log_info, "Flushing completed\n");

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_core_flush(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_flush_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (context->op == flush_core)
		ocf_cache_log(cache, log_info, "Flushing core\n");
	else if (context->op == purge_core)
		ocf_cache_log(cache, log_info, "Purging core\n");

	context->cache->flushing_interrupted = 0;
	_ocf_mngt_flush_core(context, _ocf_mngt_flush_core_complete);
}

static
struct ocf_pipeline_properties _ocf_mngt_core_flush_pipeline_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_flush_context),
	.finish = _ocf_mngt_flush_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_begin_flush),
		OCF_PL_STEP(_ocf_mngt_core_flush),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_core_flush(ocf_core_t core,
		ocf_mngt_core_flush_end_t cmpl, void *priv)
{
	ocf_pipeline_t pipeline;
	struct ocf_mngt_cache_flush_context *context;
	ocf_cache_t cache;
	int result;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(core, priv, -OCF_ERR_CACHE_STANDBY);

	if (!ocf_cache_is_device_attached(cache)) {
		ocf_cache_log(cache, log_err, "Cannot flush core - "
				"cache device is detached\n");
		OCF_CMPL_RET(core, priv, -OCF_ERR_CACHE_DETACHED);
	}

	if (!core->opened) {
		ocf_core_log(core, log_err, "Cannot flush - core is in "
				"inactive state\n");
		OCF_CMPL_RET(core, priv, -OCF_ERR_CORE_IN_INACTIVE_STATE);
	}

	if (!cache->mngt_queue) {
		ocf_core_log(core, log_err,
				"Cannot flush core - no flush queue set\n");
		OCF_CMPL_RET(core, priv, -OCF_ERR_INVAL);
	}

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_core_flush_pipeline_properties);
	if (result)
		OCF_CMPL_RET(core, priv, -OCF_ERR_NO_MEM);

	context = ocf_pipeline_get_priv(pipeline);

	context->pipeline = pipeline;
	context->cmpl.flush_core = cmpl;
	context->priv = priv;
	context->cache = cache;
	context->op = flush_core;
	context->core = core;

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_cache_invalidate(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_flush_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	ocf_metadata_start_exclusive_access(&cache->metadata_lock);
	result = ocf_metadata_sparse_range(cache, context->purge.core_id, 0,
			context->purge.end_byte);
	ocf_metadata_end_exclusive_access(&cache->metadata_lock);

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, result);
}

static void _ocf_mngt_cache_detach_cline_range(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_flush_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;
	ocf_cache_line_t free_detached_before, free_detached_after;

	free_detached_before =
		env_atomic_read(&cache->free_detached.runtime->curr_size);

	ocf_metadata_start_exclusive_access(&cache->metadata_lock);
	result = ocf_metadata_detach_cline_range(cache, context->begin,
			context->end);
	ocf_metadata_end_exclusive_access(&cache->metadata_lock);

	free_detached_after =
		env_atomic_read(&cache->free_detached.runtime->curr_size);

	if (unlikely(result && free_detached_before != free_detached_after)) {
		ocf_cache_log(cache, log_err, "Error %d during detaching cache"
				" lines %u - %u\n", result, context->begin,
				context->end);
		ENV_BUG();
	}

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, result);
}

int ocf_mngt_cache_attach_cline_range(ocf_cache_t cache,
		ocf_cache_line_t begin, ocf_cache_line_t end)
{
	int result;
	ocf_cache_line_t free_detached_before, free_detached_after;

	free_detached_before =
		env_atomic_read(&cache->free_detached.runtime->curr_size);

	ocf_metadata_start_exclusive_access(&cache->metadata_lock);
	result = ocf_metadata_restore_cline_range(cache, begin, end);
	ocf_metadata_end_exclusive_access(&cache->metadata_lock);

	free_detached_after =
		env_atomic_read(&cache->free_detached.runtime->curr_size);

	if (unlikely(result && free_detached_before != free_detached_after)) {
		ocf_cache_log(cache, log_err, "Error %d during restoring cache"
				" lines %u - %u\n", result, begin, end);
		ENV_BUG();
	}

	return result;
}

static
struct ocf_pipeline_properties _ocf_mngt_cache_purge_pipeline_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_flush_context),
	.finish = _ocf_mngt_flush_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_begin_flush),
		OCF_PL_STEP(_ocf_mngt_cache_flush),
		OCF_PL_STEP(_ocf_mngt_cache_invalidate),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_cache_purge(ocf_cache_t cache,
		ocf_mngt_cache_purge_end_t cmpl, void *priv)
{
	ocf_pipeline_t pipeline;
	int result = 0;
	struct ocf_mngt_cache_flush_context *context;

	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_STANDBY);

	if (!ocf_cache_is_device_attached(cache))
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_DETACHED);

	if (!cache->mngt_queue) {
		ocf_cache_log(cache, log_err,
				"Cannot purge cache - no flush queue set\n");
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);
	}

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_cache_purge_pipeline_properties);
	if (result)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_NO_MEM);

	context = ocf_pipeline_get_priv(pipeline);

	context->pipeline = pipeline;
	context->cmpl.purge_cache = cmpl;
	context->priv = priv;
	context->cache = cache;
	context->op = purge_cache;
	context->begin = 0;
	context->end = ocf_metadata_line_count(&cache->metadata);
	context->purge.core_id = OCF_CORE_ID_INVALID;
	context->purge.end_byte = ~0ULL;

	ocf_pipeline_next(context->pipeline);
}

static struct ocf_pipeline_properties
_ocf_mngt_cache_detach_cline_range_pipeline_props = {
	.priv_size = sizeof(struct ocf_mngt_cache_flush_context),
	.finish = _ocf_mngt_flush_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_begin_flush),
		OCF_PL_STEP(_ocf_mngt_cache_flush),
		OCF_PL_STEP(_ocf_mngt_begin_cache_lines_invalidate),
		OCF_PL_STEP(_ocf_mngt_cache_detach_cline_range),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_cache_detach_cline_range(ocf_cache_t cache,
		ocf_cache_line_t begin, ocf_cache_line_t end,
		ocf_mngt_cache_purge_end_t cmpl, void *priv)
{
	ocf_pipeline_t pipeline;
	int result = 0;
	struct ocf_mngt_cache_flush_context *context;

	OCF_CHECK_NULL(cache);

	if (begin > end)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	if (end > ocf_metadata_line_count(&cache->metadata))
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_cache_detach_cline_range_pipeline_props);
	if (result)
		OCF_CMPL_RET(cache, priv, -OCF_ERR_NO_MEM);

	context = ocf_pipeline_get_priv(pipeline);

	context->begin = begin;
	context->end = end;
	context->pipeline = pipeline;
	context->cmpl.purge_cache = cmpl;
	context->priv = priv;
	context->cache = cache;
	context->op = purge_cache;

	ocf_pipeline_next(context->pipeline);
}

static
struct ocf_pipeline_properties _ocf_mngt_core_purge_pipeline_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_flush_context),
	.finish = _ocf_mngt_flush_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_begin_flush),
		OCF_PL_STEP(_ocf_mngt_core_flush),
		OCF_PL_STEP(_ocf_mngt_cache_invalidate),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_core_purge(ocf_core_t core,
		ocf_mngt_core_purge_end_t cmpl, void *priv)
{
	ocf_pipeline_t pipeline;
	struct ocf_mngt_cache_flush_context *context;
	ocf_cache_t cache;
	ocf_core_id_t core_id;
	int result = 0;
	uint64_t core_size = ~0ULL;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);
	core_id = ocf_core_get_id(core);

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(core, priv, -OCF_ERR_CACHE_STANDBY);

	if (!ocf_cache_is_device_attached(cache))
		OCF_CMPL_RET(core, priv, -OCF_ERR_CACHE_DETACHED);

	if (!cache->mngt_queue) {
		ocf_core_log(core, log_err,
				"Cannot purge core - no flush queue set\n");
		OCF_CMPL_RET(core, priv, -OCF_ERR_INVAL);
	}

	core_size = ocf_volume_get_length(&cache->core[core_id].volume);

	result = ocf_pipeline_create(&pipeline, cache,
			&_ocf_mngt_core_purge_pipeline_properties);
	if (result)
		OCF_CMPL_RET(core, priv, -OCF_ERR_NO_MEM);

	context = ocf_pipeline_get_priv(pipeline);

	context->pipeline = pipeline;
	context->cmpl.purge_core = cmpl;
	context->priv = priv;
	context->cache = cache;
	context->op = purge_core;
	context->purge.core_id = core_id;
	context->purge.end_byte = core_size ?: ~0ULL;
	context->core = core;

	ocf_pipeline_next(context->pipeline);
}

void ocf_mngt_cache_flush_interrupt(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return;

	ocf_cache_log(cache, log_alert, "Flushing interrupt\n");
	cache->flushing_interrupted = 1;
}

struct ocf_mngt_cache_set_cleaning_context
{
	/* pipeline for switching cleaning policy */
	ocf_pipeline_t pipeline;
	/* target cache */
	ocf_cache_t cache;
	/* new cleaning policy */
	ocf_cleaning_t new_policy;
	/* old cleaning policy */
	ocf_cleaning_t old_policy;
	/* completion function */
	ocf_mngt_cache_set_cleaning_policy_end_t cmpl;
	/* completion function */
	void *priv;

	struct {
		bool cleaner_frozen : 1;
	} flags;
};

static void _ocf_mngt_cache_cleaning_set_policy_zero_cb(void *priv)
{
	struct ocf_mngt_cache_set_cleaning_context *context = priv;
	ocf_cache_t cache = context->cache;

	ocf_cleaning_deinitialize(cache);

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_cache_cleaning_set_policy_deinitialize(
		ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_set_cleaning_context *context = priv;
	ocf_cache_t cache = context->cache;

	env_refcnt_freeze(&cache->cleaner.refcnt);
	context->flags.cleaner_frozen = true;

	env_refcnt_register_zero_cb(&cache->cleaner.refcnt,
			_ocf_mngt_cache_cleaning_set_policy_zero_cb,
			context);
}

static void _ocf_mngt_cache_cleaning_set_policy_initialize(
		ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_set_cleaning_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_cleaning_t new_policy = context->new_policy;
	int result;

	result = ocf_cleaning_initialize(cache, new_policy);

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, result);
}

static void _ocf_mngt_cache_cleaning_set_policy_prepopulate_cmpl(void *priv,
		int error)
{
	struct ocf_mngt_cache_set_cleaning_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static void _ocf_mngt_cache_cleaning_set_policy_prepopulate(
		ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_set_cleaning_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_cleaning_t new_policy = context->new_policy;

	ocf_cleaning_prepopulate(cache, new_policy,
			_ocf_mngt_cache_cleaning_set_policy_prepopulate_cmpl,
			context);
}

static void _ocf_mngt_cache_cleaning_set_policy_update_cmpl(void *priv,
		int error)
{
	struct ocf_mngt_cache_set_cleaning_context *context = priv;

	if (error) {
		ocf_pipeline_rollback(context->pipeline, error);
		return;
	}

	ocf_pipeline_next(context->pipeline);
}


static void _ocf_mngt_cache_cleaning_set_policy_update(
		ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_set_cleaning_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_cleaning_t new_policy = context->new_policy;

	__set_cleaning_policy(cache, context->new_policy);

	env_refcnt_unfreeze(&cache->cleaner.refcnt);
	context->flags.cleaner_frozen = false;

	ocf_cleaning_update(cache, new_policy,
			_ocf_mngt_cache_cleaning_set_policy_update_cmpl,
			context);
}

static void _ocf_mngt_cleaning_set_finish(ocf_pipeline_t pipeline, void *priv,
		int error)
{
	struct ocf_mngt_cache_set_cleaning_context *context = priv;
	ocf_cache_t cache = context->cache;
	ocf_cleaning_t old_policy = context->old_policy;
	ocf_cleaning_t new_policy = context->new_policy;
	ocf_cleaning_t emergency_policy = ocf_cleaning_nop;

	if (error) {
		ocf_cache_log(cache, log_info, "Failed to initialize %s "
				"cleaning policy. Setting %s instead\n",
				ocf_cleaning_get_name(new_policy),
				ocf_cleaning_get_name(emergency_policy));
		new_policy = emergency_policy;
	} else {
		ocf_cache_log(cache, log_info, "Changing cleaning policy from "
				"%s to %s\n", ocf_cleaning_get_name(old_policy),
				ocf_cleaning_get_name(new_policy));
	}

	__set_cleaning_policy(cache, new_policy);

	if (context->flags.cleaner_frozen)
		env_refcnt_unfreeze(&cache->cleaner.refcnt);

	context->cmpl(context->priv, error);

	ocf_pipeline_destroy(pipeline);
}

static
struct ocf_pipeline_properties ocf_mngt_cache_cleaning_set_policy_properties = {
	.priv_size = sizeof(struct ocf_mngt_cache_set_cleaning_context),
	.finish = _ocf_mngt_cleaning_set_finish,
	.steps = {
		OCF_PL_STEP(_ocf_mngt_cache_cleaning_set_policy_deinitialize),
		OCF_PL_STEP(_ocf_mngt_cache_cleaning_set_policy_initialize),
		OCF_PL_STEP(_ocf_mngt_cache_cleaning_set_policy_prepopulate),
		OCF_PL_STEP(_ocf_mngt_cache_cleaning_set_policy_update),
		OCF_PL_STEP_TERMINATOR(),
	},
	.rollback = {
		OCF_PL_STEP(_ocf_mngt_cache_cleaning_set_policy_deinitialize),
		OCF_PL_STEP_TERMINATOR(),
	},
};

void ocf_mngt_cache_cleaning_set_policy(ocf_cache_t cache,
		ocf_cleaning_t new_policy,
		ocf_mngt_cache_set_cleaning_policy_end_t cmpl, void *priv)
{
	struct ocf_mngt_cache_set_cleaning_context *context;
	ocf_pipeline_t pipeline;
	ocf_cleaning_t old_policy;
	int ret = 0;

	OCF_CHECK_NULL(cache);

	if (new_policy < 0 || new_policy >= ocf_cleaning_max)
		OCF_CMPL_RET(priv, -OCF_ERR_INVAL);

	if (ocf_cache_is_standby(cache))
		OCF_CMPL_RET(priv, -OCF_ERR_CACHE_STANDBY);

	if (!ocf_cache_is_device_attached(cache)) {
		ocf_cache_log(cache, log_err, "Cannot change cleaning policy - "
				"cache device is detached\n");
		OCF_CMPL_RET(priv, -OCF_ERR_CACHE_DETACHED);
	}

	old_policy = cache->cleaner.policy;

	if (new_policy == old_policy) {
		ocf_cache_log(cache, log_info, "Cleaning policy %s is already "
				"set\n", ocf_cleaning_get_name(old_policy));
		OCF_CMPL_RET(priv, 0);
	}

	if (cache->conf_meta->cleaner_disabled)
		OCF_CMPL_RET(priv, -OCF_ERR_CLEANER_DISABLED);

	ret = ocf_pipeline_create(&pipeline, cache,
			&ocf_mngt_cache_cleaning_set_policy_properties);
	if (ret)
		OCF_CMPL_RET(priv, ret);

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->cache = cache;
	context->pipeline = pipeline;
	context->new_policy = new_policy;
	context->old_policy = old_policy;
	context->priv = priv;

	OCF_PL_NEXT_RET(pipeline);
}

int ocf_mngt_cache_cleaning_get_policy(ocf_cache_t cache, ocf_cleaning_t *type)
{
	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(type);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	*type = cache->cleaner.policy;

	return 0;
}

int ocf_mngt_cache_cleaning_set_param(ocf_cache_t cache, ocf_cleaning_t type,
		uint32_t param_id, uint32_t param_value)
{
	int ret;

	OCF_CHECK_NULL(cache);

	if (type < 0 || type >= ocf_cleaning_max)
		return -OCF_ERR_INVAL;

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_cache_is_device_attached(cache))
		return -OCF_ERR_CACHE_DETACHED;

	ocf_metadata_start_exclusive_access(&cache->metadata_lock);

	ret = ocf_cleaning_set_param(cache, type, param_id, param_value);

	ocf_metadata_end_exclusive_access(&cache->metadata_lock);

	return ret;
}

int ocf_mngt_cache_cleaning_get_param(ocf_cache_t cache, ocf_cleaning_t type,
		uint32_t param_id, uint32_t *param_value)
{
	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(param_value);

	if (type < 0 || type >= ocf_cleaning_max)
		return -OCF_ERR_INVAL;

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	return ocf_cleaning_get_param(cache, type, param_id, param_value);
}
