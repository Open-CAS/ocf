/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

//#include "ocf_concurrency.h"
#include "../ocf_cache_priv.h"
#include "../ocf_priv.h"
#include "../ocf_request.h"
#include "utils_alock.h"
//#include "../utils/utils_cache_line.h"
//#include "../utils/utils_realloc.h"

#define OCF_CACHE_CONCURRENCY_DEBUG 0

#if 1 == OCF_CACHE_CONCURRENCY_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Concurrency][Cache] %s\n", __func__)

#define OCF_DEBUG_RQ(req, format, ...) \
	ocf_cache_log(req->cache, log_info, "[Concurrency][Cache][%s] %s - " \
			format"\n", OCF_READ == (req)->rw ? "RD" : "WR", \
			__func__, ##__VA_ARGS__)

#else
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_RQ(req, format, ...)
#endif

#define OCF_CACHE_LINE_ACCESS_WR	INT_MAX
#define OCF_CACHE_LINE_ACCESS_IDLE	0
#define OCF_CACHE_LINE_ACCESS_ONE_RD	1

#define _WAITERS_LIST_SIZE	(16UL * MiB)
#define _WAITERS_LIST_ENTRIES \
	(_WAITERS_LIST_SIZE / sizeof(struct ocf_alock_waiters_list))

#define _WAITERS_LIST_ITEM(cache_line) ((cache_line) % _WAITERS_LIST_ENTRIES)

struct ocf_alock_waiter {
	ocf_cache_line_t entry;
	uint32_t idx;
	struct ocf_request *req;
	ocf_req_async_lock_cb cmpl;
	struct list_head item;
	int rw;
};

struct ocf_alock_waiters_list {
	struct list_head head;
	env_spinlock lock;
};

struct ocf_alock {
	ocf_cache_t cache;
	env_mutex lock;
	env_atomic *access;
	env_atomic waiting;
	ocf_cache_line_t num_entries;
	env_allocator *allocator;
	struct ocf_alock_waiters_list waiters_lsts[_WAITERS_LIST_ENTRIES];

};

int ocf_alock_init(struct ocf_alock **self, unsigned num_entries,
		const char* name, ocf_cache_t cache)
{
	uint32_t i;
	int error = 0;
	struct ocf_alock *alock;

	OCF_DEBUG_TRACE(cache);

	alock = env_vzalloc(sizeof(*alock));
	if (!alock) {
		error = __LINE__;
		goto exit_err;
	}

	alock->cache = cache;
	alock->num_entries = num_entries;

	error = env_mutex_init(&alock->lock);
	if (error) {
		error = __LINE__;
		goto rwsem_err;
	}

	alock->access = env_vzalloc(num_entries * sizeof(alock->access[0]));

	if (!alock->access) {
		error = __LINE__;
		goto allocation_err;
	}

	alock->allocator = env_allocator_create(sizeof(struct ocf_alock_waiter), name);
	if (!alock->allocator) {
		error = __LINE__;
		goto allocation_err;
	}

	/* Init concurrency control table */
	for (i = 0; i < _WAITERS_LIST_ENTRIES; i++) {
		INIT_LIST_HEAD(&alock->waiters_lsts[i].head);
		error = env_spinlock_init(&alock->waiters_lsts[i].lock);
		if (error) {
			error = __LINE__;
			goto spinlock_err;
		}
	}

	*self = alock;
	return 0;

spinlock_err:
	while (i--)
		env_spinlock_destroy(&alock->waiters_lsts[i].lock);

allocation_err:
	if (alock->allocator)
		env_allocator_destroy(alock->allocator);

	if (alock->access)
		env_vfree(alock->access);

rwsem_err:
	env_mutex_destroy(&alock->lock);

exit_err:
	ocf_cache_log(cache, log_err, "Cannot initialize cache concurrency, "
			"ERROR %d", error);
	if (alock)
		env_vfree(alock);

	*self = NULL;
	return -1;
}

void ocf_alock_deinit(struct ocf_alock **self)
{
	struct ocf_alock *concurrency = *self;
	int i;

	if (!concurrency)
		return;

	OCF_DEBUG_TRACE(concurrency->cache);

	env_mutex_destroy(&concurrency->lock);

	for (i = 0; i < _WAITERS_LIST_ENTRIES; i++)
		env_spinlock_destroy(&concurrency->waiters_lsts[i].lock);

	if (concurrency->access)
		env_vfree(concurrency->access);

	if (concurrency->allocator)
		env_allocator_destroy(concurrency->allocator);

	env_vfree(concurrency);

	*self = NULL;
}

size_t ocf_alock_size(unsigned num_entries)
{
	size_t size;

	size = sizeof(env_atomic);
	size *= num_entries;

	size += sizeof(struct ocf_alock);

	return size;
}

static inline bool ocf_alock_waitlist_is_empty_locked(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	bool are = false;
	struct list_head *iter;
	uint32_t idx = _WAITERS_LIST_ITEM(entry);
	struct ocf_alock_waiters_list *lst = &alock->waiters_lsts[idx];
	struct ocf_alock_waiter *waiter;

	/* If list empty that means there are no waiters on cache entry */
	if (list_empty(&lst->head))
		return true;

	list_for_each(iter, &lst->head) {
		waiter = list_entry(iter, struct ocf_alock_waiter, item);

		if (waiter->entry == entry) {
			are = true;
			break;
		}
	}

	return !are;
}

static inline void ocf_alock_waitlist_add(struct ocf_alock *alock,
		ocf_cache_line_t entry, struct ocf_alock_waiter *waiter)
{
	uint32_t idx = _WAITERS_LIST_ITEM(entry);
	struct ocf_alock_waiters_list *lst = &alock->waiters_lsts[idx];

	list_add_tail(&waiter->item, &lst->head);
}


#define ocf_alock_waitlist_lock(cncrrncy, entry, flags) \
	do { \
		uint32_t idx = _WAITERS_LIST_ITEM(entry); \
		struct ocf_alock_waiters_list *lst = &cncrrncy->waiters_lsts[idx]; \
		env_spinlock_lock_irqsave(&lst->lock, flags); \
	} while (0)

#define ocf_alock_waitlist_unlock(cncrrncy, entry, flags) \
	do { \
		uint32_t idx = _WAITERS_LIST_ITEM(entry); \
		struct ocf_alock_waiters_list *lst = &cncrrncy->waiters_lsts[idx]; \
		env_spinlock_unlock_irqrestore(&lst->lock, flags); \
	} while (0)


bool ocf_alock_trylock_entry_wr(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	env_atomic *access = &alock->access[entry];
	int prev = env_atomic_cmpxchg(access, OCF_CACHE_LINE_ACCESS_IDLE,
			OCF_CACHE_LINE_ACCESS_WR);

	if (prev == OCF_CACHE_LINE_ACCESS_IDLE)
		return true;
	else
		return false;
}

static inline bool ocf_alock_trylock_entry_rd_idle(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	env_atomic *access = &alock->access[entry];
	int prev = env_atomic_cmpxchg(access, OCF_CACHE_LINE_ACCESS_IDLE,
			OCF_CACHE_LINE_ACCESS_ONE_RD);

	return (prev == OCF_CACHE_LINE_ACCESS_IDLE);
}

static inline bool ocf_alock_trylock_entry_rd(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	env_atomic *access = &alock->access[entry];

	return !!env_atomic_add_unless(access, 1, OCF_CACHE_LINE_ACCESS_WR);
}

static inline void ocf_alock_unlock_entry_wr(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	env_atomic *access = &alock->access[entry];

	ENV_BUG_ON(env_atomic_read(access) != OCF_CACHE_LINE_ACCESS_WR);
	env_atomic_set(access, OCF_CACHE_LINE_ACCESS_IDLE);
}

static inline void ocf_alock_unlock_entry_rd(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	env_atomic *access = &alock->access[entry];

	ENV_BUG_ON(env_atomic_read(access) == 0);
	ENV_BUG_ON(env_atomic_read(access) == OCF_CACHE_LINE_ACCESS_WR);
	env_atomic_dec(access);
}

static inline bool ocf_alock_trylock_entry_wr2wr(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	env_atomic *access = &alock->access[entry];

	ENV_BUG_ON(env_atomic_read(access) != OCF_CACHE_LINE_ACCESS_WR);
	return true;
}

static inline bool ocf_alock_trylock_entry_wr2rd(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	env_atomic *access = &alock->access[entry];

	ENV_BUG_ON(env_atomic_read(access) != OCF_CACHE_LINE_ACCESS_WR);
	env_atomic_set(access, OCF_CACHE_LINE_ACCESS_ONE_RD);
	return true;
}

static inline bool ocf_alock_trylock_entry_rd2wr(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	env_atomic *access = &alock->access[entry];

	int v = env_atomic_read(access);

	ENV_BUG_ON(v == OCF_CACHE_LINE_ACCESS_IDLE);
	ENV_BUG_ON(v == OCF_CACHE_LINE_ACCESS_WR);

	v = env_atomic_cmpxchg(access, OCF_CACHE_LINE_ACCESS_ONE_RD,
			OCF_CACHE_LINE_ACCESS_WR);

	return (v == OCF_CACHE_LINE_ACCESS_ONE_RD);
}

static inline bool ocf_alock_trylock_entry_rd2rd(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	env_atomic *access = &alock->access[entry];

	int v = env_atomic_read(access);

	ENV_BUG_ON(v == OCF_CACHE_LINE_ACCESS_IDLE);
	ENV_BUG_ON(v == OCF_CACHE_LINE_ACCESS_WR);

	return true;
}

static void ocf_alock_entry_locked(struct ocf_alock *alock,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl)
{
	if (env_atomic_dec_return(&req->lock_remaining) == 0) {
		/* All cache entry locked, resume request */
		OCF_DEBUG_RQ(req, "Resume");
		ENV_BUG_ON(!cmpl);
		env_atomic_dec(&alock->waiting);
		cmpl(req);
	}
}

static inline bool ocf_alock_lock_one_wr(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t entry, ocf_req_async_lock_cb cmpl,
		void *req, uint32_t idx)
{
	struct ocf_alock_waiter *waiter;
	bool waiting = false;
	unsigned long flags = 0;

	ENV_BUG_ON(!cmpl);

	if (ocf_alock_trylock_entry_wr(alock, entry)) {
		/* lock was not owned by anyone */
		cbs->line_mark_locked(req, idx, OCF_WRITE, true);
		ocf_alock_entry_locked(alock, req, cmpl);
		return true;
	}

	waiter = env_allocator_new(alock->allocator);
	if (!waiter)
		return false;

	ocf_alock_waitlist_lock(alock, entry, flags);

	/* At the moment list is protected, double check if the cache entry is
	 * unlocked
	 */
	if (ocf_alock_trylock_entry_wr(alock, entry))
		goto unlock;

	/* Setup waiters filed */
	waiter->entry = entry;
	waiter->req = req;
	waiter->idx = idx;
	waiter->cmpl = cmpl;
	waiter->rw = OCF_WRITE;
	INIT_LIST_HEAD(&waiter->item);

	/* Add to waiters list */
	ocf_alock_waitlist_add(alock, entry, waiter);
	waiting = true;

unlock:
	ocf_alock_waitlist_unlock(alock, entry, flags);

	if (!waiting) {
		cbs->line_mark_locked(req, idx, OCF_WRITE, true);
		ocf_alock_entry_locked(alock, req, cmpl);
		env_allocator_del(alock->allocator, waiter);
	}

	return true;
}

/*
 * Attempt to lock cache entry for read.
 * In case cache entry is locked,  attempt to add caller on wait list.
 */
static inline bool ocf_alock_lock_one_rd(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t entry, ocf_req_async_lock_cb cmpl,
		void *req, uint32_t idx)
{
	struct ocf_alock_waiter *waiter;
	bool waiting = false;
	unsigned long flags = 0;

	ENV_BUG_ON(!cmpl);

	if( ocf_alock_trylock_entry_rd_idle(alock, entry)) {
		/* lock was not owned by anyone */
		cbs->line_mark_locked(req, idx, OCF_READ, true);
		ocf_alock_entry_locked(alock, req, cmpl);
		return true;
	}

	waiter = env_allocator_new(alock->allocator);
	if (!waiter)
		return false;

	/* Lock waiters list */
	ocf_alock_waitlist_lock(alock, entry, flags);

	if (!ocf_alock_waitlist_is_empty_locked(alock, entry)) {
		/* No waiters at the moment */

		/* Check if read lock can be obtained */
		if (ocf_alock_trylock_entry_rd(alock, entry)) {
			/* Cache entry locked */
			goto unlock;
		}
	}

	/* Setup waiters field */
	waiter->entry = entry;
	waiter->req = req;
	waiter->idx = idx;
	waiter->cmpl = cmpl;
	waiter->rw = OCF_READ;
	INIT_LIST_HEAD(&waiter->item);

	/* Add to waiters list */
	ocf_alock_waitlist_add(alock, entry, waiter);
	waiting = true;

unlock:
	ocf_alock_waitlist_unlock(alock, entry, flags);

	if (!waiting) {
		cbs->line_mark_locked(req, idx, OCF_READ, true);
		ocf_alock_entry_locked(alock, req, cmpl);
		env_allocator_del(alock->allocator, waiter);
	}

	return true;
}

static inline void ocf_alock_unlock_one_rd_common(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t entry)
{
	bool locked = false;
	bool exchanged = true;
	uint32_t i = 0;

	uint32_t idx = _WAITERS_LIST_ITEM(entry);
	struct ocf_alock_waiters_list *lst = &alock->waiters_lsts[idx];
	struct ocf_alock_waiter *waiter;

	struct list_head *iter, *next;

	/*
	 * Lock exchange scenario
	 * 1. RD -> IDLE
	 * 2. RD -> RD
	 * 3. RD -> WR
	 */

	/* Check is requested page is on the list */
	list_for_each_safe(iter, next, &lst->head) {
		waiter = list_entry(iter, struct ocf_alock_waiter, item);

		if (entry != waiter->entry)
			continue;

		if (exchanged) {
			if (waiter->rw == OCF_WRITE)
				locked = ocf_alock_trylock_entry_rd2wr(alock, entry);
			else if (waiter->rw == OCF_READ)
				locked = ocf_alock_trylock_entry_rd2rd(alock, entry);
			else
				ENV_BUG();
		} else {
			if (waiter->rw == OCF_WRITE)
				locked = ocf_alock_trylock_entry_wr(alock, entry);
			else if (waiter->rw == OCF_READ)
				locked = ocf_alock_trylock_entry_rd(alock, entry);
			else
				ENV_BUG();
		}

		i++;

		if (locked) {
			exchanged = false;
			list_del(iter);

			cbs->line_mark_locked(waiter->req, waiter->idx,
					waiter->rw, true);
			ocf_alock_entry_locked(alock, waiter->req, waiter->cmpl);

			env_allocator_del(alock->allocator, waiter);
		} else {
			break;
		}
	}

	if (exchanged) {
		/* No exchange, no waiters on the list, unlock and return
		 * WR -> IDLE
		 */
		ocf_alock_unlock_entry_rd(alock, entry);
	}
}

bool ocf_alock_trylock_one_rd(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	return ocf_alock_trylock_entry_rd_idle(alock, entry);
}

void ocf_alock_unlock_one_rd(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t entry)
{
	unsigned long flags = 0;

	OCF_DEBUG_RQ(alock->cache, "Cache entry = %u", entry);

	/* Lock waiters list */
	ocf_alock_waitlist_lock(alock, entry, flags);
	ocf_alock_unlock_one_rd_common(alock, cbs, entry);
	ocf_alock_waitlist_unlock(alock, entry, flags);
}


static inline void ocf_alock_unlock_one_wr_common(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t entry)
{
	uint32_t i = 0;
	bool locked = false;
	bool exchanged = true;

	uint32_t idx = _WAITERS_LIST_ITEM(entry);
	struct ocf_alock_waiters_list *lst = &alock->waiters_lsts[idx];
	struct ocf_alock_waiter *waiter;

	struct list_head *iter, *next;

	/*
	 * Lock exchange scenario
	 * 1. WR -> IDLE
	 * 2. WR -> RD
	 * 3. WR -> WR
	 */

	/* Check is requested page is on the list */
	list_for_each_safe(iter, next, &lst->head) {
		waiter = list_entry(iter, struct ocf_alock_waiter, item);

		if (entry != waiter->entry)
			continue;

		if (exchanged) {
			if (waiter->rw == OCF_WRITE)
				locked = ocf_alock_trylock_entry_wr2wr(alock, entry);
			else if (waiter->rw == OCF_READ)
				locked = ocf_alock_trylock_entry_wr2rd(alock, entry);
			else
				ENV_BUG();
		} else {
			if (waiter->rw == OCF_WRITE)
				locked = ocf_alock_trylock_entry_wr(alock, entry);
			else if (waiter->rw == OCF_READ)
				locked = ocf_alock_trylock_entry_rd(alock, entry);
			else
				ENV_BUG();
		}

		i++;

		if (locked) {
			exchanged = false;
			list_del(iter);

			cbs->line_mark_locked(waiter->req, waiter->idx,
					waiter->rw, true);
			ocf_alock_entry_locked(alock, waiter->req, waiter->cmpl);

			env_allocator_del(alock->allocator, waiter);
		} else {
			break;
		}
	}

	if (exchanged) {
		/* No exchange, no waiters on the list, unlock and return
		 * WR -> IDLE
		 */
		ocf_alock_unlock_entry_wr(alock, entry);
	}
}

void ocf_alock_unlock_one_wr(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t entry)
{
	unsigned long flags = 0;

	OCF_DEBUG_RQ(alock->cache, "Cache entry = %u", entry);

	/* Lock waiters list */
	ocf_alock_waitlist_lock(alock, entry, flags);
	ocf_alock_unlock_one_wr_common(alock, cbs, entry);
	ocf_alock_waitlist_unlock(alock, entry, flags);
}

/*
 * Safely remove cache entry lock waiter from waiting list.
 * Request can be assigned with lock asynchronously at any point of time,
 * so need to check lock state under a common lock.
 */
static inline void ocf_alock_waitlist_remove_entry(struct ocf_alock *alock,
	struct ocf_alock_lock_cbs *cbs,
	struct ocf_request *req, int i, int rw)
{
	ocf_cache_line_t entry = cbs->line_get_entry(req, i);
	uint32_t idx = _WAITERS_LIST_ITEM(entry);
	struct ocf_alock_waiters_list *lst = &alock->waiters_lsts[idx];
	struct list_head *iter, *next;
	struct ocf_alock_waiter *waiter;
	unsigned long flags = 0;

	ocf_alock_waitlist_lock(alock, entry, flags);

	if (cbs->line_is_locked(req, i, rw)) {
		if (rw == OCF_READ)
			ocf_alock_unlock_one_rd_common(alock, cbs, entry);
		else
			ocf_alock_unlock_one_wr_common(alock, cbs, entry);
		cbs->line_mark_locked(req, i, rw, false);
	} else {
		list_for_each_safe(iter, next, &lst->head) {
			waiter = list_entry(iter, struct ocf_alock_waiter, item);
			if (waiter->req == req) {
				list_del(iter);
				env_allocator_del(alock->allocator, waiter);
			}
		}
	}

	ocf_alock_waitlist_unlock(alock, entry, flags);
}

/* Try to read-lock request without adding waiters. Function should be called
 * under read lock, multiple threads may attempt to acquire the lock
 * concurrently.
 */
static int ocf_alock_lock_rd_fast(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req)
{
	int32_t i;
	ocf_cache_line_t entry;
	int ret = OCF_LOCK_ACQUIRED;

	OCF_DEBUG_RQ(req, "Lock");

	ENV_BUG_ON(env_atomic_read(&req->lock_remaining));

	for (i = 0; i < req->core_line_count; i++) {
		if (!cbs->line_needs_lock(req, i)) {
			/* nothing to lock */
			continue;
		}

		entry = cbs->line_get_entry(req, i);
		ENV_BUG_ON(entry >= alock->num_entries);
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_READ));
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_WRITE));

		if( ocf_alock_trylock_entry_rd_idle(alock, entry)) {
			/* cache entry locked */
			cbs->line_mark_locked(req, i, OCF_READ, true);
		} else {
			/* Not possible to lock all cachelines */
			ret = OCF_LOCK_NOT_ACQUIRED;
			OCF_DEBUG_RQ(req, "NO Lock, cache entry = %u", entry);
			break;
		}
	}

	/* Check if request is locked */
	if (ret == OCF_LOCK_NOT_ACQUIRED) {
		/* Request is not locked, discard acquired locks */
		for (; i >= 0; i--) {
			if (!cbs->line_needs_lock(req, i)) {
				/* nothing to discard */
				continue;
			}

			entry = cbs->line_get_entry(req, i);

			if (cbs->line_is_locked(req, i, OCF_READ)) {
				ocf_alock_unlock_one_rd(alock, cbs, entry);
				cbs->line_mark_locked(req, i, OCF_READ, false);
			}
		}
	}

	return ret;
}

/*
 * Read-lock request cache lines. Must be called under cacheline concurrency
 * write lock.
 */
static int ocf_alock_lock_rd_slow(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl)
{
	int32_t i;
	ocf_cache_line_t entry;
	int ret = OCF_LOCK_NOT_ACQUIRED;

	ENV_BUG_ON(env_atomic_read(&req->lock_remaining));

	env_atomic_inc(&alock->waiting);
	env_atomic_set(&req->lock_remaining, req->core_line_count);
	env_atomic_inc(&req->lock_remaining);

	for (i = 0; i < req->core_line_count; i++) {
		if (!cbs->line_needs_lock(req, i)) {
			/* nothing to lock */
			env_atomic_dec(&req->lock_remaining);
			continue;
		}

		entry = cbs->line_get_entry(req, i);
		ENV_BUG_ON(entry >= alock->num_entries);
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_READ));
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_WRITE));

		if (!ocf_alock_lock_one_rd(alock, cbs, entry, cmpl, req, i)) {
			/* lock not acquired and not added to wait list */
			ret = -OCF_ERR_NO_MEM;
			goto err;
		}
	}

	if (env_atomic_dec_return(&req->lock_remaining) == 0) {
		ret = OCF_LOCK_ACQUIRED;
		env_atomic_dec(&alock->waiting);
	}

	return ret;

err:
	for (; i >= 0; i--) {
		if (!cbs->line_needs_lock(req, i))
			continue;

		ocf_alock_waitlist_remove_entry(alock, cbs, req, i ,OCF_READ);
	}
	env_atomic_set(&req->lock_remaining, 0);
	env_atomic_dec(&alock->waiting);

	return ret;

}

int ocf_alock_lock_rd(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl)
{
	int lock;

	lock = ocf_alock_lock_rd_fast(alock, cbs, req);

	if (lock != OCF_LOCK_ACQUIRED) {
		env_mutex_lock(&alock->lock);
		lock = ocf_alock_lock_rd_slow(alock, cbs, req, cmpl);
		env_mutex_unlock(&alock->lock);
	}

	return lock;
}

/* Try to write-lock request without adding waiters. Function should be called
 * under read lock, multiple threads may attempt to acquire the lock
 * concurrently. */
static int ocf_alock_lock_wr_fast(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req)
{
	int32_t i;
	ocf_cache_line_t entry;
	int ret = OCF_LOCK_ACQUIRED;

	ENV_BUG_ON(env_atomic_read(&req->lock_remaining));

	for (i = 0; i < req->core_line_count; i++) {
		if (!cbs->line_needs_lock(req, i)) {
			/* nothing to lock */
			continue;
		}

		entry = cbs->line_get_entry(req, i);
		ENV_BUG_ON(entry >= alock->num_entries);
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_READ));
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_WRITE));

		if (ocf_alock_trylock_entry_wr(alock, entry)) {
			/* cache entry locked */
			cbs->line_mark_locked(req, i, OCF_WRITE, true);
		} else {
			/* Not possible to lock all cachelines */
			ret = OCF_LOCK_NOT_ACQUIRED;
			OCF_DEBUG_RQ(req, "NO Lock, cache entry = %u", entry);
			break;
		}
	}

	/* Check if request is locked */
	if (ret == OCF_LOCK_NOT_ACQUIRED) {
		/* Request is not locked, discard acquired locks */
		for (; i >= 0; i--) {
			if (!cbs->line_needs_lock(req, i))
				continue;

			entry = cbs->line_get_entry(req, i);

			if (cbs->line_is_locked(req, i, OCF_WRITE)) {
				ocf_alock_unlock_one_wr(alock, cbs, entry);
				cbs->line_mark_locked(req, i, OCF_WRITE, false);
			}
		}
	}

	return ret;
}

/*
 * Write-lock request cache lines. Must be called under cacheline concurrency
 * write lock.
 */
static int ocf_alock_lock_wr_slow(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl)
{
	int32_t i;
	ocf_cache_line_t entry;
	int ret = OCF_LOCK_NOT_ACQUIRED;

	ENV_BUG_ON(env_atomic_read(&req->lock_remaining));
	ENV_BUG_ON(!cmpl);

	env_atomic_inc(&alock->waiting);
	env_atomic_set(&req->lock_remaining, req->core_line_count);
	env_atomic_inc(&req->lock_remaining);

	for (i = 0; i < req->core_line_count; i++) {

		if (!cbs->line_needs_lock(req, i)) {
			/* nothing to lock */
			env_atomic_dec(&req->lock_remaining);
			continue;
		}

		entry = cbs->line_get_entry(req, i);
		ENV_BUG_ON(entry >= alock->num_entries);
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_READ));
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_WRITE));

		if (!ocf_alock_lock_one_wr(alock, cbs, entry, cmpl, req, i)) {
			/* lock not acquired and not added to wait list */
			ret = -OCF_ERR_NO_MEM;
			goto err;
		}
	}

	if (env_atomic_dec_return(&req->lock_remaining) == 0) {
		ret = OCF_LOCK_ACQUIRED;
		env_atomic_dec(&alock->waiting);
	}

	return ret;

err:
	for (; i >= 0; i--) {
		if (!cbs->line_needs_lock(req, i))
			continue;

		ocf_alock_waitlist_remove_entry(alock, cbs, req, i, OCF_WRITE);
	}
	env_atomic_set(&req->lock_remaining, 0);
	env_atomic_dec(&alock->waiting);

	return ret;
}

int ocf_alock_lock_wr(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl)
{
	int lock;

	lock = ocf_alock_lock_wr_fast(alock, cbs, req);

	if (lock != OCF_LOCK_ACQUIRED) {
		env_mutex_lock(&alock->lock);
		lock = ocf_alock_lock_wr_slow(alock, cbs, req, cmpl);
		env_mutex_unlock(&alock->lock);
	}

	return lock;
}

void ocf_alock_unlock_rd(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req)
{
	int32_t i;
	ocf_cache_line_t entry;

	OCF_DEBUG_RQ(req, "Unlock");

	for (i = 0; i < req->core_line_count; i++) {
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_WRITE));

		if (!cbs->line_is_acting(req, i))
			continue;

		if (!cbs->line_is_locked(req, i, OCF_READ))
			continue;

		entry = cbs->line_get_entry(req, i);

		ENV_BUG_ON(entry >= alock->num_entries);

		ocf_alock_unlock_one_rd(alock, cbs, entry);
		cbs->line_mark_locked(req, i, OCF_READ, false);
	}
}

void ocf_alock_unlock_wr(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req)
{
	int32_t i;
	ocf_cache_line_t entry;

	OCF_DEBUG_RQ(req, "Unlock");

	for (i = 0; i < req->core_line_count; i++) {
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_READ));

		if (!cbs->line_is_acting(req, i))
			continue;

		if (!cbs->line_is_locked(req, i, OCF_WRITE))
			continue;

		entry = cbs->line_get_entry(req, i);

		ENV_BUG_ON(entry >= alock->num_entries);

		ocf_alock_unlock_one_wr(alock, cbs, entry);
		cbs->line_mark_locked(req, i, OCF_WRITE, false);
	}
}

void ocf_alock_unlock(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req)
{
	int32_t i;
	ocf_cache_line_t entry;

	OCF_DEBUG_RQ(req, "Unlock");

	for (i = 0; i < req->core_line_count; i++) {
		if (!cbs->line_is_acting(req, i))
			continue;

		entry = cbs->line_get_entry(req, i);
		ENV_BUG_ON(entry >= alock->num_entries);

		if (cbs->line_is_locked(req, i, OCF_READ) &&
				cbs->line_is_locked(req, i, OCF_WRITE)) {
			ENV_BUG();
		} else if (cbs->line_is_locked(req, i, OCF_READ)) {
			ocf_alock_unlock_one_rd(alock, cbs, entry);
			cbs->line_mark_locked(req, i, OCF_READ, false);
		} else if (cbs->line_is_locked(req, i, OCF_WRITE)) {
			ocf_alock_unlock_one_wr(alock, cbs, entry);
			cbs->line_mark_locked(req, i, OCF_WRITE, false);
		}
	}
}

void ocf_alock_unlock_one(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req, uint32_t idx)
{
	ocf_cache_line_t entry = cbs->line_get_entry(req, idx);

	ENV_BUG_ON(!cbs->line_is_acting(req, idx));

	if (cbs->line_is_locked(req, idx, OCF_READ) &&
			cbs->line_is_locked(req, idx, OCF_WRITE)) {
		ENV_BUG();
	} else if (cbs->line_is_locked(req, idx, OCF_READ)) {
		ocf_alock_unlock_one_rd(alock, cbs, entry);
		cbs->line_mark_locked(req, idx, OCF_READ, false);
	} else if (cbs->line_is_locked(req, idx, OCF_WRITE)) {
		ocf_alock_unlock_one_wr(alock, cbs, entry);
		cbs->line_mark_locked(req, idx, OCF_WRITE, false);
	} else {
		ENV_BUG();
	}
}

bool ocf_cache_line_is_used(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	ENV_BUG_ON(entry >= alock->num_entries);

	if (env_atomic_read(&(alock->access[entry])))
		return true;

	return !ocf_alock_waitlist_is_empty(alock, entry);
}

bool ocf_alock_waitlist_is_empty(struct ocf_alock *alock,
		ocf_cache_line_t entry)
{
	bool empty;
	unsigned long flags = 0;

	ENV_BUG_ON(entry >= alock->num_entries);

	/* Lock waiters list */
	ocf_alock_waitlist_lock(alock, entry, flags);

	empty = ocf_alock_waitlist_is_empty_locked(alock, entry);

	ocf_alock_waitlist_unlock(alock, entry, flags);

	return empty;
}

uint32_t ocf_alock_waitlist_count(struct ocf_alock *alock)
{
	return env_atomic_read(&alock->waiting);
}
