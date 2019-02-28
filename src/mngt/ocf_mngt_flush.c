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
#include "../utils/utils_cleaner.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_part.h"
#include "../ocf_def_priv.h"

static inline void  _ocf_mngt_begin_flush(struct ocf_cache *cache)
{
	env_mutex_lock(&cache->flush_mutex);

	env_atomic_inc(&cache->flush_started);

	env_waitqueue_wait(cache->pending_dirty_wq,
			!env_atomic_read(&cache->pending_dirty_requests));
}

static inline void _ocf_mngt_end_flush(struct ocf_cache *cache)
{
	ENV_BUG_ON(env_atomic_dec_return(&cache->flush_started) < 0);

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

static void _ocf_mngt_free_sectors(void *tbl)
{
	env_vfree(tbl);
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

	/* TODO: Alloc flush_containers and data tables in single allocation */
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

static void _ocf_mngt_flush_end(void *private_data, int error)
{
	struct flush_container *fc = private_data;

	fc->ticks2 = env_get_tick_count();

	env_atomic_cmpxchg(fc->error, 0, error);

	env_atomic_set(&fc->completed, 1);
	env_atomic_inc(fc->progress);
	env_waitqueue_wake_up(fc->wq);
}

static int _ocf_mngt_flush_containers(ocf_cache_t cache,
		struct flush_container *fctbl, uint32_t fcnum,
		bool allow_interruption)
{
	uint32_t fc_to_flush;
	env_waitqueue wq;
	env_atomic progress; /* incremented each time flushing of a portion of a
				container is completed */
	env_atomic error;
	ocf_core_t core;
	bool interrupt = false;
	int i;

	if (fcnum == 0)
		return 0;

	env_waitqueue_init(&wq);

	/* Sort data. Smallest sectors first (0...n). */
	ocf_cleaner_sort_flush_containers(fctbl, fcnum);

	env_atomic_set(&error, 0);

	for (i = 0; i < fcnum; i++) {
		fctbl[i].attribs.cache_line_lock = true;
		fctbl[i].attribs.cmpl_context = &fctbl[i];
		fctbl[i].attribs.cmpl_fn = _ocf_mngt_flush_end;
		fctbl[i].attribs.io_queue = cache->flush_queue;
		fctbl[i].cache = cache;
		fctbl[i].progress = &progress;
		fctbl[i].error = &error;
		fctbl[i].wq = &wq;
		fctbl[i].flush_portion = OCF_MNG_FLUSH_MIN;
		fctbl[i].ticks1 = 0;
		fctbl[i].ticks2 = UINT_MAX;
		env_atomic_set(&fctbl[i].completed, 1);
	}

	for (fc_to_flush = fcnum; fc_to_flush > 0;) {
		env_atomic_set(&progress, 0);
		for (i = 0; i < fcnum; i++) {
			if (!env_atomic_read(&fctbl[i].completed))
				continue;

			core = &cache->core[fctbl[i].core_id];
			env_atomic_set(&core->flushed, fctbl[i].iter);
			env_atomic_set(&fctbl[i].completed, 0);

			if (fctbl[i].iter == fctbl[i].count || interrupt ||
					env_atomic_read(&error)) {
				fc_to_flush--;
				continue;
			}

			_ocf_mngt_flush_portion(&fctbl[i]);
		}
		if (fc_to_flush) {
			ocf_metadata_unlock(cache, OCF_METADATA_WR);
			env_cond_resched();
			env_waitqueue_wait(wq, env_atomic_read(&progress));
			ocf_metadata_lock(cache, OCF_METADATA_WR);
		}
		if (cache->flushing_interrupted && !interrupt) {
			if (allow_interruption) {
				interrupt = true;
				ocf_cache_log(cache, log_info,
						"Flushing interrupted by "
						"user\n");
			} else {
				ocf_cache_log(cache, log_err,
						"Cannot interrupt flushing\n");
			}
		}
	}

	return interrupt ? -OCF_ERR_FLUSHING_INTERRUPTED :
			env_atomic_read(&error);
}

static int _ocf_mngt_flush_core(ocf_core_t core, bool allow_interruption)
{
	ocf_core_id_t core_id = ocf_core_get_id(core);
	ocf_cache_t cache = core->volume.cache;
	struct flush_container fc;
	int ret;

	ocf_metadata_lock(cache, OCF_METADATA_WR);

	ret = _ocf_mngt_get_sectors(cache, core_id,
			&fc.flush_data, &fc.count);
	if (ret) {
		ocf_core_log(core, log_err, "Flushing operation aborted, "
				"no memory\n");
		goto out;
	}

	fc.core_id = core_id;
	fc.iter = 0;

	ret = _ocf_mngt_flush_containers(cache, &fc, 1, allow_interruption);

	_ocf_mngt_free_sectors(fc.flush_data);

out:
	ocf_metadata_unlock(cache, OCF_METADATA_WR);
	return ret;
}

static int _ocf_mngt_flush_all_cores(ocf_cache_t cache, bool allow_interruption)
{
	struct flush_container *fctbl = NULL;
	uint32_t fcnum = 0;
	int ret;

	ocf_metadata_lock(cache, OCF_METADATA_WR);

	/* Get all 'dirty' sectors for all cores */
	ret = _ocf_mngt_get_flush_containers(cache, &fctbl, &fcnum);
	if (ret) {
		ocf_cache_log(cache, log_err, "Flushing operation aborted, "
				"no memory\n");
		goto out;
	}

	ret = _ocf_mngt_flush_containers(cache, fctbl, fcnum,
			allow_interruption);

	_ocf_mngt_free_flush_containers(fctbl, fcnum);

out:
	ocf_metadata_unlock(cache, OCF_METADATA_WR);
	return ret;
}

/**
 * Flush all the dirty data stored on cache (all the cores attached to it)
 * @param cache cache instance to which operation applies
 * @param allow_interruption whenever to allow interruption of flushing process.
 *		if set to 0, all requests to interrupt flushing will be ignored
 */
static int _ocf_mng_cache_flush(ocf_cache_t cache, bool interruption)
{
	int result = 0;
	int i, j;

	env_atomic_set(&cache->flush_in_progress, 1);
	cache->flushing_interrupted = 0;
	do {
		env_cond_resched();
		result = _ocf_mngt_flush_all_cores(cache, interruption);
		if (result) {
			/* Cleaning error */
			break;
		}
	} while (ocf_mngt_cache_is_dirty(cache));

	env_atomic_set(&cache->flush_in_progress, 0);
	for (i = 0, j = 0; i < OCF_CORE_MAX; i++) {
		if (!env_bit_test(i, cache->conf_meta->valid_core_bitmap))
			continue;

		env_atomic_set(&cache->core[i].flushed, 0);

		if (++j == cache->conf_meta->core_count)
			break;
	}

	return result;
}

int ocf_mngt_cache_flush(ocf_cache_t cache, bool interruption)
{
	int result = 0;

	OCF_CHECK_NULL(cache);

	if (!ocf_cache_is_device_attached(cache)) {
		ocf_cache_log(cache, log_err, "Cannot flush cache - "
				"cache device is detached\n");
		return -OCF_ERR_INVAL;
	}

	if (ocf_cache_is_incomplete(cache)) {
		ocf_cache_log(cache, log_err, "Cannot flush cache - "
				"cache is in incomplete state\n");
		return -OCF_ERR_CACHE_IN_INCOMPLETE_STATE;
	}

	if (!cache->flush_queue) {
		ocf_cache_log(cache, log_err,
				"Cannot flush cache - no flush queue set\n");
		return -OCF_ERR_INVAL;
	}

	ocf_cache_log(cache, log_info, "Flushing cache\n");

	_ocf_mngt_begin_flush(cache);

	result = _ocf_mng_cache_flush(cache, interruption);

	_ocf_mngt_end_flush(cache);

	if (!result)
		ocf_cache_log(cache, log_info, "Flushing cache completed\n");

	return result;
}

static int _ocf_mng_core_flush(ocf_core_t core, bool interruption)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_core_id_t core_id = ocf_core_get_id(core);
	int ret;

	cache->flushing_interrupted = 0;
	do {
		env_cond_resched();
		ret = _ocf_mngt_flush_core(core, interruption);
		if (ret == -OCF_ERR_FLUSHING_INTERRUPTED ||
				ret == -OCF_ERR_WRITE_CORE) {
			break;
		}
	} while (env_atomic_read(&cache->core_runtime_meta[core_id].
			dirty_clines));

	env_atomic_set(&core->flushed, 0);

	return ret;
}

int ocf_mngt_core_flush(ocf_core_t core, bool interruption)
{
	ocf_cache_t cache;
	int ret = 0;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);

	if (!ocf_cache_is_device_attached(cache)) {
		ocf_cache_log(cache, log_err, "Cannot flush core - "
				"cache device is detached\n");
		return -OCF_ERR_INVAL;
	}

	if (!core->opened) {
		ocf_core_log(core, log_err, "Cannot flush - core is in "
				"inactive state\n");
		return -OCF_ERR_CORE_IN_INACTIVE_STATE;
	}

	if (!cache->flush_queue) {
		ocf_core_log(core, log_err,
				"Cannot flush core - no flush queue set\n");
		return -OCF_ERR_INVAL;
	}

	ocf_core_log(core, log_info, "Flushing\n");

	_ocf_mngt_begin_flush(cache);

	ret = _ocf_mng_core_flush(core, interruption);

	_ocf_mngt_end_flush(cache);

	if (!ret)
		ocf_cache_log(cache, log_info, "Flushing completed\n");

	return ret;
}

int ocf_mngt_core_purge(ocf_core_t core, bool interruption)
{
	ocf_cache_t cache;
	ocf_core_id_t core_id;
	int result = 0;
	uint64_t core_size = ~0ULL;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);
	core_id = ocf_core_get_id(core);

	if (!cache->flush_queue) {
		ocf_core_log(core, log_err,
				"Cannot purge core - no flush queue set\n");
		return -OCF_ERR_INVAL;
	}

	core_size = ocf_volume_get_length(&cache->core[core_id].volume);
	core_size = core_size ?: ~0ULL;

	_ocf_mngt_begin_flush(cache);

	ocf_core_log(core, log_info, "Purging\n");

	result = _ocf_mng_core_flush(core, interruption);

	if (result)
		goto out;

	OCF_METADATA_LOCK_WR();
	result = ocf_metadata_sparse_range(cache, core_id, 0,
			core_size);
	OCF_METADATA_UNLOCK_WR();

out:
	_ocf_mngt_end_flush(cache);

	return result;
}

int ocf_mngt_cache_purge(ocf_cache_t cache, bool interruption)
{
	int result = 0;

	OCF_CHECK_NULL(cache);

	if (!cache->flush_queue) {
		ocf_cache_log(cache, log_err,
				"Cannot purge cache - no flush queue set\n");
		return -OCF_ERR_INVAL;
	}

	_ocf_mngt_begin_flush(cache);

	ocf_cache_log(cache, log_info, "Purging\n");

	result = _ocf_mng_cache_flush(cache, interruption);

	if (result)
		goto out;

	OCF_METADATA_LOCK_WR();
	result = ocf_metadata_sparse_range(cache, OCF_CORE_ID_INVALID, 0,
			~0ULL);
	OCF_METADATA_UNLOCK_WR();

out:
	_ocf_mngt_end_flush(cache);

	return result;
}

int ocf_mngt_cache_flush_interrupt(ocf_cache_t cache)
{
	OCF_CHECK_NULL(cache);

	ocf_cache_log(cache, log_alert, "Flushing interrupt\n");
	cache->flushing_interrupted = 1;
	return 0;
}

int ocf_mngt_cache_cleaning_set_policy(ocf_cache_t cache, ocf_cleaning_t type)
{

	ocf_cleaning_t old_type;
	int ret;

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

	if (type != old_type) {
		/*
		 * If operation was successfull or cleaning policy changed,
		 * we need to flush superblock.
		 */
		if (ocf_metadata_flush_superblock(cache)) {
			ocf_cache_log(cache, log_err,
				"Failed to flush superblock! Changes "
				"in cache config are not persistent!\n");
		}
	}

	ocf_cache_log(cache, log_info, "Changing cleaning policy from "
			"%s to %s\n", cleaning_policy_ops[old_type].name,
			cleaning_policy_ops[type].name);

	ocf_metadata_unlock(cache, OCF_METADATA_WR);

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

	if (ret == 0) {
		/*
		 * If operation was successfull or cleaning policy changed,
		 * we need to flush superblock.
		 */
		if (ocf_metadata_flush_superblock(cache)) {
			ocf_cache_log(cache, log_err,
				"Failed to flush superblock! Changes "
				"in cache config are not persistent!\n");
		}
	}

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
