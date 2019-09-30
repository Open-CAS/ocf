/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_mngt_common.h"
#include "ocf_mngt_core_priv.h"
#include "../ocf_priv.h"
#include "../ocf_ctx_priv.h"
#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../ocf_request.h"
#include "../eviction/ops.h"
#include "../ocf_logger_priv.h"
#include "../ocf_queue_priv.h"
#include "../engine/engine_common.h"

/* Close if opened */
int cache_mngt_core_close(ocf_core_t core)
{
	if (!core->opened)
		return -OCF_ERR_CORE_IN_INACTIVE_STATE;

	ocf_volume_close(&core->front_volume);
	ocf_volume_deinit(&core->front_volume);

	ocf_volume_close(&core->volume);
	ocf_volume_deinit(&core->volume);
	core->opened = false;

	return 0;
}

/* Remove core from cleaning policy */
void cache_mngt_core_remove_from_cleaning_pol(ocf_core_t core)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_core_id_t core_id = ocf_core_get_id(core);
	ocf_cleaning_t clean_pol_type;

	ocf_metadata_start_exclusive_access(&cache->metadata.lock);

	clean_pol_type = cache->conf_meta->cleaning_policy_type;
	if (cache->core[core_id].opened) {
		if (cleaning_policy_ops[clean_pol_type].remove_core) {
			cleaning_policy_ops[clean_pol_type].
				remove_core(cache, core_id);
		}
	}

	ocf_metadata_end_exclusive_access(&cache->metadata.lock);
}

/* Deinitialize core metadata in attached metadata */
void cache_mngt_core_deinit_attached_meta(ocf_core_t core)
{
	int retry = 1;
	uint64_t core_size = 0;
	ocf_cleaning_t clean_pol_type;
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_core_id_t core_id = ocf_core_get_id(core);

	core_size = ocf_volume_get_length(&core->volume);
	if (!core_size)
		core_size = ~0ULL;

	ocf_metadata_start_exclusive_access(&cache->metadata.lock);

	clean_pol_type = cache->conf_meta->cleaning_policy_type;
	while (retry) {
		retry = 0;
		if (cleaning_policy_ops[clean_pol_type].purge_range) {
			retry = cleaning_policy_ops[clean_pol_type].purge_range(cache,
					core_id, 0, core_size);
		}

		if (!retry) {
			/* Remove from collision_table and Partition. Put in FREELIST */
			retry = ocf_metadata_sparse_range(cache, core_id, 0,
					core_size);
		}

		if (retry) {
			ocf_metadata_end_exclusive_access(&cache->metadata.lock);
			env_msleep(100);
			ocf_metadata_start_exclusive_access(
					&cache->metadata.lock);
		}
	}

	ocf_metadata_end_exclusive_access(&cache->metadata.lock);
}

/* Mark core as removed in metadata */
void cache_mngt_core_remove_from_meta(ocf_core_t core)
{
	ocf_cache_t cache = ocf_core_get_cache(core);

	ocf_metadata_start_exclusive_access(&cache->metadata.lock);

	/* In metadata mark data this core was removed from cache */
	core->conf_meta->valid = false;

	/* Clear UUID of core */
	ocf_mngt_core_clear_uuid_metadata(core);
	core->conf_meta->seq_no = OCF_SEQ_NO_INVALID;

	ocf_metadata_end_exclusive_access(&cache->metadata.lock);
}

/* Deinit in-memory structures related to this core */
void cache_mngt_core_remove_from_cache(ocf_core_t core)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_core_id_t core_id = ocf_core_get_id(core);

	env_free(core->counters);
	core->counters = NULL;
	core->added = false;
	env_bit_clear(core_id, cache->conf_meta->valid_core_bitmap);

	if (!core->opened && --cache->ocf_core_inactive_count == 0)
		env_bit_clear(ocf_cache_state_incomplete, &cache->cache_state);

	cache->conf_meta->core_count--;
}

void ocf_mngt_cache_put(ocf_cache_t cache)
{
	ocf_ctx_t ctx;

	OCF_CHECK_NULL(cache);

	if (ocf_refcnt_dec(&cache->refcnt.cache) == 0) {
		ctx = cache->owner;
		ocf_metadata_deinit(cache);
		env_vfree(cache);
		ocf_ctx_put(ctx);
	}
}

int ocf_mngt_cache_get_by_name(ocf_ctx_t ctx, const char *name, size_t name_len,
		ocf_cache_t *cache)
{
	struct ocf_cache *instance = NULL;
	struct ocf_cache *iter = NULL;

	OCF_CHECK_NULL(ctx);
	OCF_CHECK_NULL(cache);

	/* Lock caches list */
	env_rmutex_lock(&ctx->lock);

	list_for_each_entry(iter, &ctx->caches, list) {
		if (!env_strncmp(ocf_cache_get_name(iter), OCF_CACHE_NAME_SIZE,
				name, name_len)) {
			instance = iter;
			break;
		}
	}

	if (instance) {
		/* if cache is either fully initialized or during recovery */
		if (!ocf_refcnt_inc(&instance->refcnt.cache)) {
			/* Cache not initialized yet */
			instance = NULL;
		}
	}

	env_rmutex_unlock(&ctx->lock);

	if (!instance)
		return -OCF_ERR_CACHE_NOT_EXIST;

	*cache = instance;

	return 0;
}

typedef void (*ocf_lock_fn_t)(ocf_async_lock_waiter_t waiter);

typedef int (*ocf_trylock_fn_t)(ocf_async_lock_t lock);

typedef void (*ocf_unlock_fn_t)(ocf_async_lock_t lock);

struct ocf_mngt_cache_lock_context {
	ocf_cache_t cache;
	ocf_unlock_fn_t unlock_fn;
	ocf_mngt_cache_lock_end_t cmpl;
	void *priv;
};

static void _ocf_mngt_cache_lock_complete(
		ocf_async_lock_waiter_t waiter, int error)
{
	struct ocf_mngt_cache_lock_context *context;
	ocf_cache_t cache;

	context = ocf_async_lock_waiter_get_priv(waiter);
	cache = context->cache;

	if (error) {
		ocf_mngt_cache_put(cache);
		goto out;
	}

	if (env_bit_test(ocf_cache_state_stopping, &cache->cache_state)) {
		/* Cache already stopping, do not allow any operation */
		context->unlock_fn(ocf_async_lock_waiter_get_lock(waiter));
		ocf_mngt_cache_put(cache);
		error = -OCF_ERR_CACHE_NOT_EXIST;
	}

out:
	context->cmpl(context->cache, context->priv, error);
}

static void _ocf_mngt_cache_lock(ocf_cache_t cache,
		ocf_mngt_cache_lock_end_t cmpl, void *priv,
		ocf_lock_fn_t lock_fn, ocf_unlock_fn_t unlock_fn)
{
	ocf_async_lock_waiter_t waiter;
	struct ocf_mngt_cache_lock_context *context;

	if (ocf_mngt_cache_get(cache))
		OCF_CMPL_RET(cache, priv, -OCF_ERR_CACHE_NOT_EXIST);

	waiter = ocf_async_lock_new_waiter(&cache->lock,
			_ocf_mngt_cache_lock_complete);
	if (!waiter) {
		ocf_mngt_cache_put(cache);
		OCF_CMPL_RET(cache, priv, -OCF_ERR_NO_MEM);
	}

	context = ocf_async_lock_waiter_get_priv(waiter);
	context->cache = cache;
	context->unlock_fn = unlock_fn;
	context->cmpl = cmpl;
	context->priv = priv;

	lock_fn(waiter);
}

static int _ocf_mngt_cache_trylock(ocf_cache_t cache,
		ocf_trylock_fn_t trylock_fn, ocf_unlock_fn_t unlock_fn)
{
	int result;

	if (ocf_mngt_cache_get(cache))
		return -OCF_ERR_CACHE_NOT_EXIST;

	result = trylock_fn(&cache->lock);
	if (result)
		return result;

	if (env_bit_test(ocf_cache_state_stopping, &cache->cache_state)) {
		/* Cache already stopping, do not allow any operation */
		unlock_fn(&cache->lock);
		return -OCF_ERR_CACHE_NOT_EXIST;
	}

	return 0;
}

static void _ocf_mngt_cache_unlock(ocf_cache_t cache,
		ocf_unlock_fn_t unlock_fn)
{
	unlock_fn(&cache->lock);
	ocf_mngt_cache_put(cache);
}

int ocf_mngt_cache_lock_init(ocf_cache_t cache)
{
	return ocf_async_lock_init(&cache->lock,
			sizeof(struct ocf_mngt_cache_lock_context));
}

void ocf_mngt_cache_lock_deinit(ocf_cache_t cache)
{
	ocf_async_lock_deinit(&cache->lock);
}

void ocf_mngt_cache_lock(ocf_cache_t cache,
		ocf_mngt_cache_lock_end_t cmpl, void *priv)
{
	OCF_CHECK_NULL(cache);

	_ocf_mngt_cache_lock(cache, cmpl, priv,
			ocf_async_lock, ocf_async_unlock);
}

int ocf_mngt_cache_trylock(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

	return _ocf_mngt_cache_trylock(cache,
			ocf_async_trylock, ocf_async_unlock);
}

void ocf_mngt_cache_unlock(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

	_ocf_mngt_cache_unlock(cache, ocf_async_unlock);
}

void ocf_mngt_cache_read_lock(ocf_cache_t cache,
		ocf_mngt_cache_lock_end_t cmpl, void *priv)
{
	OCF_CHECK_NULL(cache);

	_ocf_mngt_cache_lock(cache, cmpl, priv,
			ocf_async_read_lock, ocf_async_read_unlock);
}

int ocf_mngt_cache_read_trylock(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

	return _ocf_mngt_cache_trylock(cache,
			ocf_async_read_trylock, ocf_async_read_unlock);
}

void ocf_mngt_cache_read_unlock(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

	_ocf_mngt_cache_unlock(cache, ocf_async_read_unlock);
}

bool ocf_mngt_cache_is_locked(ocf_cache_t cache)
{
	return ocf_async_is_locked(&cache->lock);
}

/* if cache is either fully initialized or during recovery */
static bool _ocf_mngt_cache_try_get(ocf_cache_t cache)
{
	return !!ocf_refcnt_inc(&cache->refcnt.cache);
}

int ocf_mngt_cache_get(ocf_cache_t cache)
{
	if (!_ocf_mngt_cache_try_get(cache))
		return -OCF_ERR_CACHE_NOT_AVAIL;

	return 0;
}

static int _ocf_mngt_cache_get_list_cpy(ocf_ctx_t ocf_ctx, ocf_cache_t **list,
		uint32_t *size)
{
	int result = 0;
	uint32_t count = 0, i = 0;
	ocf_cache_t iter;

	*list = NULL;
	*size = 0;

	env_rmutex_lock(&ocf_ctx->lock);

	list_for_each_entry(iter, &ocf_ctx->caches, list) {
		count++;
	}

	if (!count)
		goto END;

	*list = env_vmalloc(sizeof((*list)[0]) * count);
	if (*list == NULL) {
		result = -ENOMEM;
		goto END;
	}

	list_for_each_entry(iter, &ocf_ctx->caches, list) {
		if (_ocf_mngt_cache_try_get(iter))
			(*list)[i++] = iter;
	}

	if (i) {
		/* Update size if cache list */
		*size = i;
	} else {
		env_vfree(*list);
		*list = NULL;
	}

END:
	env_rmutex_unlock(&ocf_ctx->lock);
	return result;
}

int ocf_mngt_cache_visit(ocf_ctx_t ocf_ctx, ocf_mngt_cache_visitor_t visitor,
		void *cntx)
{
	ocf_cache_t *list;
	uint32_t size, i;
	int result;

	OCF_CHECK_NULL(ocf_ctx);
	OCF_CHECK_NULL(visitor);

	result = _ocf_mngt_cache_get_list_cpy(ocf_ctx, &list, &size);
	if (result)
		return result;

	if (size == 0)
		return 0;

	/* Iterate over caches */
	for (i = 0; i < size; i++) {
		ocf_cache_t this = list[i];

		result = visitor(this, cntx);

		if (result)
			break;
	}

	/* Put caches */
	for (i = 0; i < size; i++)
		ocf_mngt_cache_put(list[i]);

	env_vfree(list);

	return result;
}

int ocf_mngt_cache_visit_reverse(ocf_ctx_t ocf_ctx,
		ocf_mngt_cache_visitor_t visitor, void *cntx)
{
	ocf_cache_t *list;
	uint32_t size, i;
	int result;

	OCF_CHECK_NULL(ocf_ctx);
	OCF_CHECK_NULL(visitor);

	result = _ocf_mngt_cache_get_list_cpy(ocf_ctx, &list, &size);
	if (result)
		return result;

	if (size == 0)
		return 0;

	/* Iterate over caches */
	for (i = size; i; i--) {
		ocf_cache_t this = list[i - 1];

		result = visitor(this, cntx);

		if (result)
			break;
	}

	/* Put caches */
	for (i = 0; i < size; i++)
		ocf_mngt_cache_put(list[i]);

	env_vfree(list);

	return result;
}
