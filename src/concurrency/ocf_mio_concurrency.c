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

struct ocf_mio_alock
{
	unsigned first_page;
	unsigned num_pages;
};

static bool ocf_mio_lock_line_needs_lock(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index)
{
	return true;
}

static bool ocf_mio_lock_line_is_acting(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index)
{
	return true;
}

static bool ocf_mio_lock_line_is_locked(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index, int rw)
{
	struct metadata_io_request *m_req = (struct metadata_io_request *)req;

	if (rw == OCF_WRITE)
		return env_bit_test(index, &m_req->map);
	else
		return false;
}

static void ocf_mio_lock_line_mark_locked(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index, int rw, bool locked)
{
	struct metadata_io_request *m_req = (struct metadata_io_request *)req;

	if (rw == OCF_READ)
		return;
	if (locked)
		env_bit_set(index, &m_req->map);
	else
		env_bit_clear(index, &m_req->map);
}

static ocf_cache_line_t ocf_mio_lock_line_get_entry(
		struct ocf_alock *alock, struct ocf_request *req,
		unsigned index)
{
	struct ocf_mio_alock *mio_alock = (void*)alock + ocf_alock_obj_size();
	struct metadata_io_request *m_req = (struct metadata_io_request *)req;
	unsigned page = m_req->page + index;

	ENV_BUG_ON(page < mio_alock->first_page);
	ENV_BUG_ON(page >= mio_alock->first_page + mio_alock->num_pages);

	return page - mio_alock->first_page;
}

static struct ocf_alock_lock_cbs ocf_mio_conc_cbs = {
		.line_needs_lock = ocf_mio_lock_line_needs_lock,
		.line_is_acting = ocf_mio_lock_line_is_acting,
		.line_is_locked = ocf_mio_lock_line_is_locked,
		.line_mark_locked = ocf_mio_lock_line_mark_locked,
		.line_get_entry = ocf_mio_lock_line_get_entry
};

int ocf_mio_async_lock(struct ocf_alock *alock,
		struct metadata_io_request *m_req,
		ocf_req_async_lock_cb cmpl)
{
	return ocf_alock_lock_wr(alock, &m_req->req, cmpl);
}

void ocf_mio_async_unlock(struct ocf_alock *alock,
		struct metadata_io_request *m_req)
{
	ocf_alock_unlock_wr(alock, &m_req->req);
	m_req->map = 0;
}


#define ALLOCATOR_NAME_FMT "ocf_%s_mio_concurrency"
#define ALLOCATOR_NAME_MAX (sizeof(ALLOCATOR_NAME_FMT) + OCF_CACHE_NAME_SIZE)

int ocf_mio_concurrency_init(struct ocf_alock **self,
		unsigned first_page, unsigned num_pages,
		ocf_cache_t cache)
{
	struct ocf_alock *alock;
	struct ocf_mio_alock *mio_alock;
	size_t base_size = ocf_alock_obj_size();
	char name[ALLOCATOR_NAME_MAX];
	int ret;

	ret = snprintf(name, sizeof(name), ALLOCATOR_NAME_FMT,
			ocf_cache_get_name(cache));
	if (ret < 0)
		return ret;
	if (ret >= ALLOCATOR_NAME_MAX)
		return -ENOSPC;

	alock = env_vzalloc(base_size + sizeof(struct ocf_mio_alock));
	if (!alock)
		return -OCF_ERR_NO_MEM;

	ret = ocf_alock_init_inplace(alock, num_pages, name, &ocf_mio_conc_cbs, cache);
	if (ret)
		return ret;

	mio_alock = (void*)alock + base_size;
	mio_alock->first_page = first_page;
	mio_alock->num_pages = num_pages;

	*self = alock;
	return 0;
}

void ocf_mio_concurrency_deinit(struct ocf_alock **self)
{
	ocf_alock_deinit(self);
}
