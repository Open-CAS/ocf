/*
 * Copyright(c) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_concurrency.h"
#include "../metadata/metadata_io.h"
#include "../ocf_priv.h"
#include "../ocf_request.h"
#include "../utils/utils_alock.h"
#include "../utils/utils_cache_line.h"

static bool ocf_coll_update_lock_line_needs_lock(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index)
{
	return true;
}

static bool ocf_coll_update_lock_line_is_acting(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index){
	return true;
}

static bool ocf_coll_update_lock_line_is_locked(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index, int rw)
{
	struct metadata_io_request *m_req = (struct metadata_io_request *)req;

	if (rw == OCF_WRITE)
		return env_bit_test(index, &m_req->map);
	else
		return false;
}

static void ocf_coll_update_lock_line_mark_locked(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index, int rw, bool locked){
	struct metadata_io_request *m_req = (struct metadata_io_request *)req;

	if (rw == OCF_READ)
		return;
	if (locked)
		env_bit_set(index, &m_req->map);
	else
		env_bit_clear(index, &m_req->map);
}

static ocf_cache_line_t ocf_coll_update_lock_line_get_entry(
		struct ocf_alock *alock, struct ocf_request *req,
		unsigned index)
{
	struct metadata_io_request *m_req = (struct metadata_io_request *)req;

	return m_req->page + index;
}

static struct ocf_alock_lock_cbs ocf_coll_update_conc_cbs = {
		.line_needs_lock = ocf_coll_update_lock_line_needs_lock,
		.line_is_acting = ocf_coll_update_lock_line_is_acting,
		.line_is_locked = ocf_coll_update_lock_line_is_locked,
		.line_mark_locked = ocf_coll_update_lock_line_mark_locked,
		.line_get_entry = ocf_coll_update_lock_line_get_entry
};

int ocf_coll_update_async_lock(struct ocf_alock *alock,
		struct metadata_io_request *m_req,
		ocf_req_async_lock_cb cmpl)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_coll_update_conc_cbs;

	return ocf_alock_lock_wr(alock, cbs, &m_req->req, cmpl);
}

void ocf_coll_update_async_unlock(struct ocf_alock *alock,
		struct metadata_io_request *m_req)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_coll_update_conc_cbs;

	ocf_alock_unlock_wr(alock, cbs, &m_req->req);
	m_req->map = 0;
}


#define ALLOCATOR_NAME_FMT "ocf_%s_coll_upd_concurrency"
#define ALLOCATOR_NAME_MAX (sizeof(ALLOCATOR_NAME_FMT) + OCF_CACHE_NAME_SIZE)

int ocf_coll_update_concurrency_init(struct ocf_alock **self,
		unsigned num_pages, ocf_cache_t cache)
{
	char name[ALLOCATOR_NAME_MAX];
	int ret;

	ret = snprintf(name, sizeof(name), ALLOCATOR_NAME_FMT,
			ocf_cache_get_name(cache));
	if (ret < 0)
		return ret;
	if (ret >= ALLOCATOR_NAME_MAX)
		return -ENOSPC;

	return ocf_alock_init(self, num_pages, name, cache);
}

void ocf_coll_update_concurrency_deinit(struct ocf_alock **self)
{
	ocf_alock_deinit(self);
}
