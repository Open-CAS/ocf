/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#ifndef OCF_UTILS_ALOCK_H_
#define OCF_UTILS_ALOCK_H_

/**
 * @brief Lock result - Lock acquired successfully
 */
#define OCF_LOCK_ACQUIRED		0

/**
 * @brief Lock result - Lock not acquired, lock request added into waiting list
 */
#define OCF_LOCK_NOT_ACQUIRED		1

struct ocf_alock;

/* async request cacheline lock acquisition callback */
typedef void (*ocf_req_async_lock_cb)(struct ocf_request *req);

typedef bool (*ocf_cl_lock_line_needs_lock_cb)(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index);

typedef bool (*ocf_cl_lock_line_is_acting_cb)(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index);

typedef bool (*ocf_cl_lock_line_is_locked_cb)(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index, int rw);

typedef void (*ocf_cl_lock_line_mark_locked_cb)(struct ocf_alock *alock,
		struct ocf_request *req, unsigned index, int rw, bool locked);

typedef ocf_cache_line_t (*ocf_cl_lock_line_get_entry_cb)(
		struct ocf_alock *alock, struct ocf_request *req,
		unsigned index);

struct ocf_alock_lock_cbs
{
	ocf_cl_lock_line_needs_lock_cb line_needs_lock;
	ocf_cl_lock_line_is_acting_cb line_is_acting;
	ocf_cl_lock_line_is_locked_cb line_is_locked;
	ocf_cl_lock_line_mark_locked_cb line_mark_locked;
	ocf_cl_lock_line_get_entry_cb line_get_entry;
};

bool ocf_alock_trylock_one_rd(struct ocf_alock *alock,
		ocf_cache_line_t entry);

void ocf_alock_unlock_one_rd(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t entry);

bool ocf_alock_trylock_entry_wr(struct ocf_alock *alock,
		ocf_cache_line_t entry);

void ocf_alock_unlock_one_wr(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t entry_idx);

int ocf_alock_lock_rd(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl);

int ocf_alock_lock_wr(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl);

void ocf_alock_unlock_rd(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req);

void ocf_alock_unlock_wr(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req);

void ocf_alock_unlock(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req);

bool ocf_alock_waitlist_is_empty(struct ocf_alock *alock,
		ocf_cache_line_t entry);

bool ocf_alock_is_locked_exclusively(struct ocf_alock *alock,
		ocf_cache_line_t entry);

uint32_t ocf_alock_waitlist_count(struct ocf_alock *alock);

int ocf_alock_init(struct ocf_alock **self, unsigned num_entries,
		const char* name, ocf_cache_t cache);

void ocf_alock_deinit(struct ocf_alock **self);

size_t ocf_alock_size(unsigned num_entries);

#endif
