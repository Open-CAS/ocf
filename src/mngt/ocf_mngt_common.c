/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_mngt_common.h"
#include "../ocf_priv.h"
#include "../ocf_ctx_priv.h"
#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../utils/utils_part.h"
#include "../utils/utils_req.h"
#include "../utils/utils_device.h"
#include "../eviction/ops.h"
#include "../ocf_logger_priv.h"
#include "../ocf_queue_priv.h"

/* Close if opened */
int cache_mng_core_close(ocf_cache_t cache, ocf_core_id_t core_id)
{
	if (!cache->core[core_id].opened)
		return -OCF_ERR_CORE_IN_INACTIVE_STATE;

	ocf_volume_close(&cache->core[core_id].volume);
	cache->core[core_id].opened = false;

	return 0;
}

/* Remove core from cleaning policy */
void cache_mng_core_remove_from_cleaning_pol(struct ocf_cache *cache,
		int core_id)
{
	ocf_cleaning_t clean_pol_type;

	OCF_METADATA_LOCK_WR();

	clean_pol_type = cache->conf_meta->cleaning_policy_type;
	if (cache->core[core_id].opened) {
		if (cleaning_policy_ops[clean_pol_type].remove_core) {
			cleaning_policy_ops[clean_pol_type].
				remove_core(cache, core_id);
		}
	}

	OCF_METADATA_UNLOCK_WR();
}

/* Deinitialize core metadata in attached metadata */
void cache_mng_core_deinit_attached_meta(struct ocf_cache *cache, int core_id)
{
	int retry = 1;
	uint64_t core_size = 0;
	ocf_cleaning_t clean_pol_type;
	ocf_volume_t core;

	core = &cache->core[core_id].volume;

	core_size = ocf_volume_get_length(core);
	if (!core_size)
		core_size = ~0ULL;

	OCF_METADATA_LOCK_WR();

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
			OCF_METADATA_UNLOCK_WR();
			env_msleep(100);
			OCF_METADATA_LOCK_WR();
		}
	}

	OCF_METADATA_UNLOCK_WR();
}

/* Mark core as removed in metadata */
void cache_mng_core_remove_from_meta(struct ocf_cache *cache, int core_id)
{
	OCF_METADATA_LOCK_WR();

	/* In metadata mark data this core was removed from cache */
	cache->core_conf_meta[core_id].added = false;

	/* Clear UUID of core */
	ocf_metadata_clear_core_uuid(&cache->core[core_id]);
	cache->core_conf_meta[core_id].seq_no = OCF_SEQ_NO_INVALID;

	OCF_METADATA_UNLOCK_WR();
}

/* Deinit in-memory structures related to this core */
void cache_mng_core_remove_from_cache(struct ocf_cache *cache, int core_id)
{
	env_free(cache->core[core_id].counters);
	cache->core[core_id].counters = NULL;
	env_bit_clear(core_id, cache->conf_meta->valid_core_bitmap);

	if (!cache->core[core_id].opened &&
			--cache->ocf_core_inactive_count == 0) {
		env_bit_clear(ocf_cache_state_incomplete, &cache->cache_state);
	}

	cache->conf_meta->core_count--;
}

/**
 * @brief Wait for the end of asynchronous cleaning
 *
 * @param cache OCF cache instance
 * @param timeout_ms Timeout for waiting in milliseconds
 * @note When timeout is less than zero it means wait forever
 *
 * @retval 0 cleaning finished
 * @retval non-zero timeout and cleaning still in progress
 */
static int _ocf_cleaning_wait_for_finish(struct ocf_cache *cache,
		const int32_t timeout_ms)
{
	struct ocf_user_part *curr_part;
	ocf_part_id_t part_id;
	bool cleaning_active = ocf_cache_is_device_attached(cache);
	int64_t _timeout = timeout_ms;

	while (cleaning_active) {
		cleaning_active = false;

		OCF_METADATA_LOCK_WR();
		for_each_part(cache, curr_part, part_id) {
			if (env_atomic_read(&cache->cleaning[part_id])) {
				cleaning_active = true;
				break;
			}
		}
		OCF_METADATA_UNLOCK_WR();

		if (cleaning_active) {
			env_msleep(20);

			if (timeout_ms >= 0) {
				_timeout -= 20;
				if (_timeout <= 0)
					break;
			}
		}
	};

	if (cleaning_active)
		return -EBUSY;

	return 0;
}

void ocf_mngt_cache_put(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

	if (env_atomic_dec_return(&cache->ref_count) == 0) {
		ocf_free_queues(cache);
		ocf_metadata_deinit(cache);
		env_vfree(cache);
	}
}

int ocf_mngt_cache_get(ocf_ctx_t ocf_ctx, ocf_cache_id_t id, ocf_cache_t *cache)
{
	int error = 0;
	struct ocf_cache *instance = NULL;
	struct ocf_cache *iter = NULL;

	OCF_CHECK_NULL(ocf_ctx);
	OCF_CHECK_NULL(cache);

	*cache = NULL;

	if ((id < OCF_CACHE_ID_MIN) || (id > OCF_CACHE_ID_MAX)) {
		/* Cache id out of range */
		return -OCF_ERR_INVAL;
	}

	/* Lock caches list */
	env_mutex_lock(&ocf_ctx->lock);

	list_for_each_entry(iter, &ocf_ctx->caches, list) {
		if (iter->cache_id == id) {
			instance = iter;
			break;
		}
	}

	if (instance) {
		/* if cache is either fully initialized or during recovery */
		if (instance->valid_ocf_cache_device_t) {
			/* Increase reference counter */
			env_atomic_inc(&instance->ref_count);
		} else {
			/* Cache not initialized yet */
			instance = NULL;
		}
	}

	env_mutex_unlock(&ocf_ctx->lock);

	if (!instance)
		error = -OCF_ERR_CACHE_NOT_EXIST;
	else
		*cache = instance;

	return error;
}

bool ocf_mngt_is_cache_locked(ocf_cache_t cache)
{
	if (env_rwsem_is_locked(&cache->lock))
		return true;

	if (env_atomic_read(&cache->lock_waiter))
		return true;

	return false;
}

void ocf_mngt_cache_unlock(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	env_rwsem_up_write(&cache->lock);
	ocf_mngt_cache_put(cache);
}

void ocf_mngt_cache_read_unlock(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	env_rwsem_up_read(&cache->lock);
	ocf_mngt_cache_put(cache);
}

int _ocf_mngt_cache_lock(ocf_cache_t cache, bool read)
{
	int ret;

	/* Increment reference counter */
	env_atomic_inc(&cache->ref_count);

	env_atomic_inc(&cache->lock_waiter);
	if (read)
		ret = env_rwsem_down_read_interruptible(&cache->lock);
	else
		ret = env_rwsem_down_write_interruptible(&cache->lock);
	env_atomic_dec(&cache->lock_waiter);

	if (ret) {
		ocf_mngt_cache_put(cache);
		return ret;
	}

	if (env_bit_test(ocf_cache_state_stopping, &cache->cache_state)) {
		/* Cache already stooping, do not allow any operation */
		ret = -OCF_ERR_CACHE_NOT_EXIST;
		goto unlock;
	}

	/* Return, when asynchronous cleaning is finished */
	if (_ocf_cleaning_wait_for_finish(cache, 60 * 1000)) {
		/* Because of some reasons, asynchronous cleaning still active,
		 * cannot continue
		 */
		ret = -OCF_ERR_CACHE_IN_USE;
		goto unlock;
	}

	return 0;

unlock:
	if (read)
		ocf_mngt_cache_read_unlock(cache);
	else
		ocf_mngt_cache_unlock(cache);

	return ret;
}

int ocf_mngt_cache_lock(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return _ocf_mngt_cache_lock(cache, false);
}

int ocf_mngt_cache_read_lock(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);
	return _ocf_mngt_cache_lock(cache, true);
}

/* if cache is either fully initialized or during recovery */
static ocf_cache_t _ocf_mngt_cache_try_get(ocf_cache_t cache)
{
	if (!!cache->valid_ocf_cache_device_t) {
		/* Increase reference counter */
		env_atomic_inc(&cache->ref_count);
		return cache;
	}

	return NULL;
}

static int _ocf_mngt_cache_get_list_cpy(ocf_ctx_t ocf_ctx, ocf_cache_t **list,
		uint32_t *size)
{
	int result = 0;
	uint32_t count = 0, i = 0;
	struct ocf_cache *iter, *this;

	*list = NULL;
	*size = 0;

	env_mutex_lock(&ocf_ctx->lock);

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
		this = _ocf_mngt_cache_try_get(iter);

		if (this) {
			(*list)[i] = this;
			i++;
		}
	}

	if (i) {
		/* Update size if cache list */
		*size = i;
	} else {
		env_vfree(*list);
		*list = NULL;
	}

END:
	env_mutex_unlock(&ocf_ctx->lock);
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

void ocf_mngt_wait_for_io_finish(ocf_cache_t cache)
{
	uint32_t req_active = 0;

	do {
		req_active = ocf_req_get_allocated(cache);
		if (req_active)
			env_msleep(500);
	} while (req_active);
}

