/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_mngt_common.h"
#include "../ocf_priv.h"
#include "../metadata/metadata.h"
#include "../cleaning/cleaning.h"
#include "../engine/cache_engine.h"
#include "../engine/engine_common.h"
#include "../utils/utils_cleaner.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_part.h"
#include "../utils/utils_pipeline.h"
#include "../utils/utils_refcnt.h"
#include "../utils/utils_req.h"
#include "../ocf_def_priv.h"

struct ocf_mngt_cache_flush_context;
typedef void (*ocf_flush_complete_t)(struct ocf_mngt_cache_flush_context *, int);

struct flush_containers_context
{
	/* array of container descriptors */
	struct flush_container *fctbl;
	/* fctbl array size */
	uint32_t fcnum;
	/* shared error for all concurrent container flushes */
	env_atomic error;
	/* number of outstanding container flushes */
	env_atomic count;
	/* first container flush to notice interrupt sets this to 1 */
	env_atomic interrupt_seen;
	/* completion to be called after all containers are flushed */
	ocf_flush_complete_t complete;
};

/* common struct for cache/core flush/purge pipeline priv */
struct ocf_mngt_cache_flush_context
{
	/* pipeline for flush / purge */
	ocf_pipeline_t pipeline;
	/* target cache */
	ocf_cache_t cache;
	/* target core */
	ocf_core_t core;
	/* true if flush interrupt respected */
	bool allow_interruption;

	/* management operation identifier */
	enum {
		flush_cache = 0,
		flush_core,
		purge_cache,
		purge_core
	} op;

	/* ocf mngmt entry point completion */
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

	/* context for flush containers logic */
	struct flush_containers_context fcs;
};

static void _ocf_mngt_begin_flush_complete(void *priv)
{
	struct ocf_mngt_cache_flush_context *context = priv;
	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_begin_flush(ocf_pipeline_t pipeline, void *priv,
		ocf_pipeline_arg_t arg)
{
	struct ocf_mngt_cache_flush_context *context = priv;
	ocf_cache_t cache = context->cache;

	/* FIXME: need mechanism for async waiting for outstanding flushes to
	 * finish */
	env_mutex_lock(&cache->flush_mutex);

	ocf_refcnt_freeze(&cache->dirty);

	ocf_refcnt_register_zero_cb(&cache->dirty,
			_ocf_mngt_begin_flush_complete, context);
}

static void _ocf_mngt_end_flush(ocf_cache_t cache)
{
	ocf_refcnt_unfreeze(&cache->dirty);

	env_mutex_unlock(&cache->flush_mutex);
}

bool ocf_mngt_cache_is_dirty(ocf_cache_t cache)
{
	uint32_t i;

	OCF_CHECK_NULL(cache);

	for (i = 0; i < OCF_CORE_MAX; ++i) {
		if (!cache->core_conf_meta[i].added)
			continue;

		if (env_atomic_read(&(cache->core_runtime_meta[i].
				dirty_clines))) {
			return true;
		}
	}

	return false;
}

/************************FLUSH CORE CODE**************************************/
/* Returns:
 * 0 if OK and tbl & num is filled:
 * * tbl - table with sectors&cacheline
 * * num - number of items in this table.
 * other value means error.
 * NOTE:
 * Table is not sorted.
 */
static int _ocf_mngt_get_sectors(struct ocf_cache *cache, int core_id,
		struct flush_data **tbl, uint32_t *num)
{
	uint64_t core_line;
	ocf_core_id_t i_core_id;
	struct flush_data *p;
	uint32_t i, j, dirty = 0;

	dirty = env_atomic_read(&cache->core_runtime_meta[core_id].
			dirty_clines);
	if (!dirty) {
		*num = 0;
		*tbl = NULL;
		return 0;
	}

	p = env_vmalloc(dirty * sizeof(**tbl));
	if (!p)
		return -OCF_ERR_NO_MEM;

	for (i = 0, j = 0; i < cache->device->collision_table_entries; i++) {
		ocf_metadata_get_core_info(cache, i, &i_core_id, &core_line);

		if (i_core_id != core_id)
			continue;

		if (!metadata_test_valid_any(cache, i))
			continue;

		if (!metadata_test_dirty(cache, i))
			continue;

		if (ocf_cache_line_is_used(cache, i))
			continue;

		/* It's core_id cacheline and it's valid and it's dirty! */
		p[j].cache_line = i;
		p[j].core_line = core_line;
		p[j].core_id = i_core_id;
		j++;
		/* stop if all cachelines were found */
		if (j == dirty)
			break;
	}

	ocf_core_log(&cache->core[core_id], log_debug,
			"%u dirty cache lines to clean\n", j);

	if (dirty != j) {
		ocf_cache_log(cache, log_debug, "Wrong number of dirty "
				"blocks for flushing core %s (%u!=%u)\n",
				cache->core[core_id].name, j, dirty);
	}


	*tbl = p;
	*num = j;
	return 0;
}

static int _ocf_mngt_get_flush_containers(ocf_cache_t cache,
		struct flush_container **fctbl, uint32_t *fcnum)
{
	struct flush_container *fc;
	struct flush_container *curr;
	uint32_t *core_revmap;
	uint32_t num;
	uint64_t core_line;
	ocf_core_id_t core_id;
	uint32_t i, j, dirty = 0;
	int step = 0;

	/*
	 * TODO: Create containers for each physical device, not for
	 *       each core. Cores can be partitions of single device.
	 */
	num = cache->conf_meta->core_count;
	if (num == 0) {
		*fcnum = 0;
		return 0;
	}

	core_revmap = env_vzalloc(sizeof(*core_revmap) * OCF_CORE_MAX);
	if (!core_revmap)
		return -OCF_ERR_NO_MEM;

	/* TODO: Alloc fcs and data tables in single allocation */
	fc = env_vzalloc(sizeof(**fctbl) * num);
	if (!fc) {
		env_vfree(core_revmap);
		return -OCF_ERR_NO_MEM;
	}

	for (i = 0, j = 0; i < OCF_CORE_MAX; i++) {
		if (!env_bit_test(i, cache->conf_meta->valid_core_bitmap))
			continue;

		fc[j].core_id = i;
		core_revmap[i] = j;

		/* Check for dirty blocks */
		fc[j].count = env_atomic_read(&cache->
				core_runtime_meta[i].dirty_clines);
		dirty += fc[j].count;

		if (fc[j].count) {
			fc[j].flush_data = env_vmalloc(fc[j].count *
					sizeof(*fc[j].flush_data));
		}

		if (++j == cache->conf_meta->core_count)
			break;
	}

	if (!dirty) {
		env_vfree(core_revmap);
		env_vfree(fc);
		*fcnum = 0;
		return 0;
	}

	for (i = 0, j = 0; i < cache->device->collision_table_entries; i++) {
		ocf_metadata_get_core_info(cache, i, &core_id, &core_line);

		if (!metadata_test_valid_any(cache, i))
			continue;

		if (!metadata_test_dirty(cache, i))
			continue;

		if (ocf_cache_line_is_used(cache, i))
			continue;

		curr = &fc[core_revmap[core_id]];

		ENV_BUG_ON(curr->iter >= curr->count);

		/* It's core_id cacheline and it's valid and it's dirty! */
		curr->flush_data[curr->iter].cache_line = i;
		curr->flush_data[curr->iter].core_line = core_line;
		curr->flush_data[curr->iter].core_id = core_id;
		curr->iter++;

		j++;
		/* stop if all cachelines were found */
		if (j == dirty)
			break;

		OCF_COND_RESCHED(step, 1000000)
	}

	if (dirty != j) {
		ocf_cache_log(cache, log_debug, "Wrong number of dirty "
				"blocks (%u!=%u)\n", j, dirty);
		for (i = 0; i < num; i++)
			fc[i].count = fc[i].iter;
	}

	for (i = 0; i < num; i++)
		fc[i].iter = 0;

	env_vfree(core_revmap);
	*fctbl = fc;
	*fcnum = num;
	return 0;
}

static void _ocf_mngt_free_flush_containers(struct flush_container *fctbl,
	uint32_t num)
{
	int i;

	for (i = 0; i < num; i++)
		env_vfree(fctbl[i].flush_data);
	env_vfree(fctbl);
}

/*
 * OCF will try to guess disk speed etc. and adjust flushing block
 * size accordingly, however these bounds shall be respected regardless
 * of disk speed, cache line size configured etc.
 */
#define OCF_MNG_FLUSH_MIN (4*MiB / ocf_line_size(cache))
#define OCF_MNG_FLUSH_MAX (100*MiB / ocf_line_size(cache))

static void _ocf_mngt_flush_portion(struct flush_container *fc)
{
	ocf_cache_t cache = fc->cache;
	uint64_t flush_portion_div;
	uint32_t curr_count;

	flush_portion_div = env_ticks_to_msecs(fc->ticks2 - fc->ticks1);
	if (unlikely(!flush_portion_div))
		flush_portion_div = 1;

	fc->flush_portion = fc->flush_portion * 1000 / flush_portion_div;
	fc->flush_portion &= ~0x3ffULL;

	/* regardless those calculations, limit flush portion to be
	 * between OCF_MNG_FLUSH_MIN and OCF_MNG_FLUSH_MAX
	 */
	fc->flush_portion = OCF_MIN(fc->flush_portion, OCF_MNG_FLUSH_MAX);
	fc->flush_portion = OCF_MAX(fc->flush_portion, OCF_MNG_FLUSH_MIN);

	curr_count = OCF_MIN(fc->count - fc->iter, fc->flush_portion);

	ocf_cleaner_do_flush_data_async(fc->cache,
			&fc->flush_data[fc->iter],
			curr_count, &fc->attribs);

	fc->iter += curr_count;
}

static void _ocf_mngt_flush_portion_end(void *private_data, int error)
{
	struct flush_container *fc = private_data;
	struct ocf_mngt_cache_flush_context *context = fc->context;
	struct flush_containers_context *fsc = &context->fcs;
	ocf_cache_t cache = context->cache;
	ocf_core_t core = &cache->core[fc->core_id];
	bool first_interrupt;

	env_atomic_set(&core->flushed, fc->iter);

	fc->ticks2 = env_get_tick_count();

	env_atomic_cmpxchg(&fsc->error, 0, error);

	if (cache->flushing_interrupted) {
		first_interrupt = !env_atomic_cmpxchg(&fsc->interrupt_seen, 0, 1);
		if (first_interrupt) {
			if (context->allow_interruption) {
				ocf_cache_log(cache, log_info,
					"Flushing interrupted by "
					"user\n");
			} else {
				ocf_cache_log(cache, log_err,
					"Cannot interrupt flushing\n");
			}
		}
		if (context->allow_interruption) {
			env_atomic_cmpxchg(&fsc->error, 0,
					-OCF_ERR_FLUSHING_INTERRUPTED);
		}
	}

	if (env_atomic_read(&fsc->error) || fc->iter == fc->count) {
		ocf_req_put(fc->req);
		fc->end(context);
		return;
	}

	ocf_engine_push_req_front(fc->req, false);
}


static int _ofc_flush_container_step(struct ocf_request *req)
{
	struct flush_container *fc = req->priv;
	ocf_cache_t cache = fc->cache;

	ocf_metadata_lock(cache, OCF_METADATA_WR);
	_ocf_mngt_flush_portion(fc);
	ocf_metadata_unlock(cache, OCF_METADATA_WR);

	return 0;
}

static const struct ocf_io_if _io_if_flush_portion = {
	.read = _ofc_flush_container_step,
	.write = _ofc_flush_container_step,
};

static void _ocf_mngt_flush_container(
		struct ocf_mngt_cache_flush_context *context,
		struct flush_container *fc, ocf_flush_containter_coplete_t end)
{
	ocf_cache_t cache = context->cache;
	struct ocf_request *req;
	int error = 0;

	if (!fc->count)
		goto finish;

	fc->end = end;
	fc->context = context;

	req = ocf_req_new(cache->mngt_queue, NULL, 0, 0, 0);
	if (!req) {
		error = OCF_ERR_NO_MEM;
		goto finish;
	}

	req->info.internal = true;
	req->io_if = &_io_if_flush_portion;
	req->priv = fc;

	fc->req = req;
	fc->attribs.cache_line_lock = true;
	fc->attribs.cmpl_context = fc;
	fc->attribs.cmpl_fn = _ocf_mngt_flush_portion_end;
	fc->attribs.io_queue = cache->mngt_queue;
	fc->cache = cache;
	fc->flush_portion = OCF_MNG_FLUSH_MIN;
	fc->ticks1 = 0;
	fc->ticks2 = UINT_MAX;

	ocf_engine_push_req_front(fc->req, true);
	return;

finish:
	env_atomic_cmpxchg(&context->fcs.error, 0, error);
	end(context);
}

void _ocf_flush_container_complete(void *ctx)
{
	struct ocf_mngt_cache_flush_context *context = ctx;

	if (env_atomic_dec_return(&context->fcs.count)) {
		return;
	}

	_ocf_mngt_free_flush_containers(context->fcs.fctbl,
			context->fcs.fcnum);

	context->fcs.complete(context,
			env_atomic_read(&context->fcs.error));
}

static void _ocf_mngt_flush_containers(
		struct ocf_mngt_cache_flush_context *context,
		struct flush_container *fctbl,
		uint32_t fcnum, ocf_flush_complete_t complete)
{
	int i;

	if (fcnum == 0) {
		complete(context, 0);
		return;
	}

	/* Sort data. Smallest sectors first (0...n). */
	ocf_cleaner_sort_flush_containers(fctbl, fcnum);

	env_atomic_set(&context->fcs.error, 0);
	env_atomic_set(&context->fcs.count, 1);
	context->fcs.complete = complete;
	context->fcs.fctbl = fctbl;
	context->fcs.fcnum = fcnum;

	for (i = 0; i < fcnum; i++) {
		env_atomic_inc(&context->fcs.count);
		_ocf_mngt_flush_container(context, &fctbl[i],
			_ocf_flush_container_complete);
	}

	_ocf_flush_container_complete(context);
}


static void _ocf_mngt_flush_core(
	struct ocf_mngt_cache_flush_context *context,
	ocf_flush_complete_t complete)
{
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;
	ocf_core_id_t core_id = ocf_core_get_id(core);
	struct flush_container *fc;
	int ret;

	fc = env_vzalloc(sizeof(*fc));
	if (!fc) {
		complete(context, -OCF_ERR_NO_MEM);
		return;
	}

	ocf_metadata_lock(cache, OCF_METADATA_WR);

	ret = _ocf_mngt_get_sectors(cache, core_id,
			&fc->flush_data, &fc->count);
	if (ret) {
		ocf_core_log(core, log_err, "Flushing operation aborted, "
				"no memory\n");
		env_vfree(fc);
		complete(context, -OCF_ERR_NO_MEM);
		return;
	}

	fc->core_id = core_id;
	fc->iter = 0;

	_ocf_mngt_flush_containers(context, fc, 1, complete);

	ocf_metadata_unlock(cache, OCF_METADATA_WR);
}

static void _ocf_mngt_flush_all_cores(
	struct ocf_mngt_cache_flush_context *context,
	ocf_flush_complete_t complete)
{
	ocf_cache_t cache = context->cache;
	struct flush_container *fctbl = NULL;
	uint32_t fcnum = 0;
	int ret;

	if (context->op == flush_cache)
		ocf_cache_log(cache, log_info, "Flushing cache\n");
	else if (context->op == purge_cache)
		ocf_cache_log(cache, log_info, "Purging cache\n");

	env_atomic_set(&cache->flush_in_progress, 1);

	ocf_metadata_lock(cache, OCF_METADATA_WR);

	/* Get all 'dirty' sectors for all cores */
	ret = _ocf_mngt_get_flush_containers(cache, &fctbl, &fcnum);
	if (ret) {
		ocf_cache_log(cache, log_err, "Flushing operation aborted, "
				"no memory\n");
		complete(context, ret);
		return;
	}

	_ocf_mngt_flush_containers(context, fctbl, fcnum, complete);

	ocf_metadata_unlock(cache, OCF_METADATA_WR);
}

static void _ocf_mngt_flush_all_cores_complete(
		struct ocf_mngt_cache_flush_context *context, int error)
{
	ocf_cache_t cache = context->cache;
	uint32_t i, j;

	env_atomic_set(&cache->flush_in_progress, 0);

	for (i = 0, j = 0; i < OCF_CORE_MAX; i++) {
		if (!env_bit_test(i, cache->conf_meta->valid_core_bitmap))
			continue;

		env_atomic_set(&cache->core[i].flushed, 0);

		if (++j == cache->conf_meta->core_count)
			break;
	}

	if (error) {
		ocf_pipeline_finish(context->pipeline, error);
		return;
	}

	if (context->op == flush_cache)
		ocf_cache_log(cache, log_info, "Flushing cache completed\n");

	ocf_pipeline_next(context->pipeline);
}

/**
 * Flush all the dirty data stored on cache (all the cores attached to it)
 */
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
	int64_t core_id;

	if (!error) {
		switch(context->op) {
		case flush_cache:
		case purge_cache:
			ENV_BUG_ON(ocf_mngt_cache_is_dirty(cache));
			break;
		case flush_core:
		case purge_core:
			core_id = ocf_core_get_id(context->core);
			ENV_BUG_ON(env_atomic_read(&cache->core_runtime_meta
					[core_id].dirty_clines));
			break;
		}
	}

	_ocf_mngt_end_flush(context->cache);

	switch (context->op) {
	case flush_cache:
		context->cmpl.flush_cache(context->cache, context->priv, error);
		break;
	case flush_core:
		context->cmpl.flush_core(context->core, context->priv, error);
		break;
	case purge_cache:
		context->cmpl.purge_cache(context->cache, context->priv, error);
		break;
	case purge_core:
		context->cmpl.purge_core(context->core, context->priv, error);
		break;
	default:
		ENV_BUG();
	}

	ocf_pipeline_destroy(context->pipeline);
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

void ocf_mngt_cache_flush(ocf_cache_t cache, bool interruption,
		ocf_mngt_cache_flush_end_t cmpl, void *priv)
{
	ocf_pipeline_t pipeline;
	struct ocf_mngt_cache_flush_context *context;
	int result = 0;

	OCF_CHECK_NULL(cache);

	if (!ocf_cache_is_device_attached(cache)) {
		ocf_cache_log(cache, log_err, "Cannot flush cache - "
				"cache device is detached\n");
		OCF_CMPL_RET(cache, priv, -OCF_ERR_INVAL);
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
	context->allow_interruption = interruption;
	context->op = flush_cache;

	ocf_pipeline_next(context->pipeline);
}

static void _ocf_mngt_flush_core_complete(
		struct ocf_mngt_cache_flush_context *context, int error)
{
	ocf_cache_t cache = context->cache;
	ocf_core_t core = context->core;

	env_atomic_set(&core->flushed, 0);

	if (error) {
		ocf_pipeline_finish(context->pipeline, error);
		return;
	}

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

void ocf_mngt_core_flush(ocf_core_t core, bool interruption,
		ocf_mngt_core_flush_end_t cmpl, void *priv)
{
	ocf_pipeline_t pipeline;
	struct ocf_mngt_cache_flush_context *context;
	ocf_cache_t cache;
	int result;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);

	if (!ocf_cache_is_device_attached(cache)) {
		ocf_cache_log(cache, log_err, "Cannot flush core - "
				"cache device is detached\n");
		OCF_CMPL_RET(core, priv, -OCF_ERR_INVAL);
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
	context->allow_interruption = interruption;
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

	OCF_METADATA_LOCK_WR();
	result = ocf_metadata_sparse_range(cache, context->purge.core_id, 0,
			context->purge.end_byte);
	OCF_METADATA_UNLOCK_WR();

	if (result)
		ocf_pipeline_finish(context->pipeline, result);
	else
		ocf_pipeline_next(context->pipeline);
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
	context->allow_interruption = true;
	context->op = purge_cache;
	context->purge.core_id = OCF_CORE_ID_INVALID;
	context->purge.end_byte = ~0ULL;

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
	context->allow_interruption = true;
	context->op = purge_core;
	context->purge.core_id = core_id;
	context->purge.end_byte = core_size ?: ~0ULL;
	context->core = core;

	ocf_pipeline_next(context->pipeline);
}

void ocf_mngt_cache_flush_interrupt(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

	ocf_cache_log(cache, log_alert, "Flushing interrupt\n");
	cache->flushing_interrupted = 1;
}

int ocf_mngt_cache_cleaning_set_policy(ocf_cache_t cache, ocf_cleaning_t type)
{
	ocf_cleaning_t old_type;
	int ret = 0;

	OCF_CHECK_NULL(cache);

	if (type < 0 || type >= ocf_cleaning_max)
		return -OCF_ERR_INVAL;

	old_type = cache->conf_meta->cleaning_policy_type;

	if (type == old_type) {
		ocf_cache_log(cache, log_info, "Cleaning policy %s is already "
				"set\n", cleaning_policy_ops[old_type].name);
		return 0;
	}

	ocf_metadata_lock(cache, OCF_METADATA_WR);

	if (cleaning_policy_ops[old_type].deinitialize)
		cleaning_policy_ops[old_type].deinitialize(cache);

	if (cleaning_policy_ops[type].initialize) {
		if (cleaning_policy_ops[type].initialize(cache, 1)) {
			/*
			 * If initialization of new cleaning policy failed,
			 * we set cleaning policy to nop.
			 */
			type = ocf_cleaning_nop;
			ret = -OCF_ERR_INVAL;
		}
	}

	cache->conf_meta->cleaning_policy_type = type;

	ocf_metadata_unlock(cache, OCF_METADATA_WR);

	ocf_cache_log(cache, log_info, "Changing cleaning policy from "
			"%s to %s\n", cleaning_policy_ops[old_type].name,
			cleaning_policy_ops[type].name);

	return ret;
}

int ocf_mngt_cache_cleaning_get_policy(ocf_cache_t cache, ocf_cleaning_t *type)
{
	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(type);

	*type = cache->conf_meta->cleaning_policy_type;

	return 0;
}

int ocf_mngt_cache_cleaning_set_param(ocf_cache_t cache, ocf_cleaning_t type,
		uint32_t param_id, uint32_t param_value)
{
	int ret;

	OCF_CHECK_NULL(cache);

	if (type < 0 || type >= ocf_cleaning_max)
		return -OCF_ERR_INVAL;

	if (!cleaning_policy_ops[type].set_cleaning_param)
		return -OCF_ERR_INVAL;

	ocf_metadata_lock(cache, OCF_METADATA_WR);

	ret = cleaning_policy_ops[type].set_cleaning_param(cache,
			param_id, param_value);

	ocf_metadata_unlock(cache, OCF_METADATA_WR);

	return ret;
}

int ocf_mngt_cache_cleaning_get_param(ocf_cache_t cache, ocf_cleaning_t type,
		uint32_t param_id, uint32_t *param_value)
{
	int ret;

	OCF_CHECK_NULL(cache);
	OCF_CHECK_NULL(param_value);

	if (type < 0 || type >= ocf_cleaning_max)
		return -OCF_ERR_INVAL;

	if (!cleaning_policy_ops[type].get_cleaning_param)
		return -OCF_ERR_INVAL;

	ret = cleaning_policy_ops[type].get_cleaning_param(cache,
			param_id, param_value);

	return ret;
}
