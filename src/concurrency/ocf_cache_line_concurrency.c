/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_concurrency.h"
#include "../ocf_priv.h"
#include "../ocf_request.h"
#include "../utils/utils_alock.h"
#include "../utils/utils_cache_line.h"

static bool ocf_cl_lock_line_needs_lock(struct ocf_request *req,
		unsigned index)
{
	/* Remapped cachelines are assigned cacheline lock individually
	 * during eviction
	 */
	return req->map[index].status != LOOKUP_MISS &&
			req->map[index].status != LOOKUP_REMAPPED;
}

static bool ocf_cl_lock_line_is_acting(struct ocf_request *req,
		unsigned index)
{
	return req->map[index].status != LOOKUP_MISS;
}

static bool ocf_cl_lock_line_is_locked(struct ocf_request *req,
		unsigned index, int rw)
{
	if (rw == OCF_WRITE)
		return req->map[index].wr_locked;
	else
		return req->map[index].rd_locked;
}

static void ocf_cl_lock_line_mark_locked(struct ocf_request *req,
		unsigned index, int rw, bool locked)
{
	if (rw == OCF_WRITE)
		req->map[index].wr_locked = locked;
	else
		req->map[index].rd_locked = locked;
}

static ocf_cache_line_t ocf_cl_lock_line_get_entry(struct ocf_request *req,
		unsigned index)
{
	return req->map[index].coll_idx;
}

static struct ocf_alock_lock_cbs ocf_cline_conc_cbs = {
		.line_needs_lock = ocf_cl_lock_line_needs_lock,
		.line_is_acting = ocf_cl_lock_line_is_acting,
		.line_is_locked = ocf_cl_lock_line_is_locked,
		.line_mark_locked = ocf_cl_lock_line_mark_locked,
		.line_get_entry = ocf_cl_lock_line_get_entry
};

bool ocf_cache_line_try_lock_rd(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	return ocf_alock_trylock_one_rd(alock, line);
}

void ocf_cache_line_unlock_rd(struct ocf_alock *alock, ocf_cache_line_t line)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	ocf_alock_unlock_one_rd(alock, cbs, line);
}

bool ocf_cache_line_try_lock_wr(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	return ocf_alock_trylock_entry_wr(alock, line);
}

void ocf_cache_line_unlock_wr(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	ocf_alock_unlock_one_wr(alock, cbs, line);
}

int ocf_req_async_lock_rd(struct ocf_alock *alock,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	return ocf_alock_lock_rd(alock, cbs, req, cmpl);
}

int ocf_req_async_lock_wr(struct ocf_alock *alock,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	return ocf_alock_lock_wr(alock, cbs, req, cmpl);
}

void ocf_req_unlock_rd(struct ocf_alock *alock, struct ocf_request *req)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	ocf_alock_unlock_rd(alock, cbs, req);
}

void ocf_req_unlock_wr(struct ocf_alock *alock, struct ocf_request *req)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	ocf_alock_unlock_wr(alock, cbs, req);
}

void ocf_req_unlock(struct ocf_alock *alock, struct ocf_request *req)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	ocf_alock_unlock(alock, cbs, req);
}

bool ocf_cache_line_are_waiters(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	return !ocf_alock_waitlist_is_empty(alock, line);
}

bool ocf_cache_line_is_locked_exclusively(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	struct ocf_alock *alock =
			ocf_cache_line_concurrency(cache);

	return ocf_alock_is_locked_exclusively(alock, line);
}

uint32_t ocf_cache_line_concurrency_suspended_no(struct ocf_alock *alock)
{
	return ocf_alock_waitlist_count(alock);
}

#define ALLOCATOR_NAME_FMT "ocf_%s_cache_concurrency"
#define ALLOCATOR_NAME_MAX (sizeof(ALLOCATOR_NAME_FMT) + OCF_CACHE_NAME_SIZE)

int ocf_cache_line_concurrency_init(struct ocf_alock **self,
		unsigned num_clines, ocf_cache_t cache)
{
	char name[ALLOCATOR_NAME_MAX];
	int ret;

	ret = snprintf(name, sizeof(name), ALLOCATOR_NAME_FMT,
			ocf_cache_get_name(cache));
	if (ret < 0)
		return ret;
	if (ret >= ALLOCATOR_NAME_MAX)
		return -ENOSPC;

	return ocf_alock_init(self, num_clines, name, cache);
}

void ocf_cache_line_concurrency_deinit(struct ocf_alock **self)
{
	ocf_alock_deinit(self);
}

size_t ocf_cache_line_concurrency_size_of(ocf_cache_t cache)
{
	return ocf_alock_size(cache->device->collision_table_entries);
}
