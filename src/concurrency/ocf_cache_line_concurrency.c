/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_concurrency.h"
#include "../ocf_priv.h"
#include "../ocf_request.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_realloc.h"

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
	ocf_cache_line_t line;
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
	size_t access_limit;
	ocf_cache_line_t num_clines;
	env_allocator *allocator;
	struct ocf_alock_waiters_list waiters_lsts[_WAITERS_LIST_ENTRIES];

};

typedef bool (*ocf_cl_lock_line_needs_lock_cb)(struct ocf_request *req,
		unsigned index);

typedef bool (*ocf_cl_lock_line_is_acting_cb)(struct ocf_request *req,
		unsigned index);

typedef bool (*ocf_cl_lock_line_is_locked_cb)(struct ocf_request *req,
		unsigned index, int rw);

typedef void (*ocf_cl_lock_line_mark_locked_cb)(struct ocf_request *req,
		unsigned index, int rw, bool locked);


struct ocf_alock_lock_cbs
{
	ocf_cl_lock_line_needs_lock_cb line_needs_lock;
	ocf_cl_lock_line_is_acting_cb line_is_acting;
	ocf_cl_lock_line_is_locked_cb line_is_locked;
	ocf_cl_lock_line_mark_locked_cb line_mark_locked;
};

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

static struct ocf_alock_lock_cbs ocf_cline_conc_cbs = {
		.line_needs_lock = ocf_cl_lock_line_needs_lock,
		.line_is_acting = ocf_cl_lock_line_is_acting,
		.line_is_locked = ocf_cl_lock_line_is_locked,
		.line_mark_locked = ocf_cl_lock_line_mark_locked
};


/*
 *
 */

#define ALLOCATOR_NAME_FMT "ocf_%s_concurrency"
#define ALLOCATOR_NAME_MAX (sizeof(ALLOCATOR_NAME_FMT) + OCF_CACHE_NAME_SIZE)

int ocf_cache_line_concurrency_init(struct ocf_alock **self,
		unsigned num_clines, ocf_cache_t cache)
{
	uint32_t i;
	int error = 0;
	struct ocf_alock *alock;
	char name[ALLOCATOR_NAME_MAX];

	OCF_DEBUG_TRACE(cache);

	alock = env_vzalloc(sizeof(*alock));
	if (!alock) {
		error = __LINE__;
		goto exit_err;
	}

	alock->cache = cache;
	alock->num_clines = num_clines;

	error = env_mutex_init(&alock->lock);
	if (error) {
		error = __LINE__;
		goto rwsem_err;
	}

	alock->access = env_vzalloc(num_clines * sizeof(alock->access[0]));

	if (!alock->access) {
		error = __LINE__;
		goto allocation_err;
	}

	if (snprintf(name, sizeof(name), ALLOCATOR_NAME_FMT,
			ocf_cache_get_name(cache)) < 0) {
		error = __LINE__;
		goto allocation_err;
	}

	alock->allocator = env_allocator_create(sizeof(struct ocf_alock_waiter), name, false);
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

/*
 *
 */
void ocf_cache_line_concurrency_deinit(struct ocf_alock **self)
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
		OCF_REALLOC_DEINIT(&concurrency->access,
				&concurrency->access_limit);

	if (concurrency->allocator)
		env_allocator_destroy(concurrency->allocator);

	env_vfree(concurrency);

	*self = NULL;
}

size_t ocf_cache_line_concurrency_size_of(ocf_cache_t cache)
{
	size_t size;

	size = sizeof(env_atomic);
	size *= cache->device->collision_table_entries;

	size += sizeof(struct ocf_alock);

	return size;
}

/*
 *
 */
static inline bool ocf_alock_waitlist_are_waiters(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	bool are = false;
	struct list_head *iter;
	uint32_t idx = _WAITERS_LIST_ITEM(line);
	struct ocf_alock_waiters_list *lst = &alock->waiters_lsts[idx];
	struct ocf_alock_waiter *waiter;

	/* If list empty that means there are no waiters on cache line */
	if (list_empty(&lst->head))
		return false;

	list_for_each(iter, &lst->head) {
		waiter = list_entry(iter, struct ocf_alock_waiter, item);

		if (waiter->line == line) {
			are = true;
			break;
		}
	}

	return are;
}

/*
 *
 */
static inline void ocf_alock_waitlist_add(struct ocf_alock *alock,
		ocf_cache_line_t line, struct ocf_alock_waiter *waiter)
{
	uint32_t idx = _WAITERS_LIST_ITEM(line);
	struct ocf_alock_waiters_list *lst = &alock->waiters_lsts[idx];

	list_add_tail(&waiter->item, &lst->head);
}


#define ocf_alock_waitlist_lock(cncrrncy, line, flags) \
	do { \
		uint32_t idx = _WAITERS_LIST_ITEM(line); \
		struct ocf_alock_waiters_list *lst = &cncrrncy->waiters_lsts[idx]; \
		env_spinlock_lock_irqsave(&lst->lock, flags); \
	} while (0)

#define ocf_alock_waitlist_unlock(cncrrncy, line, flags) \
	do { \
		uint32_t idx = _WAITERS_LIST_ITEM(line); \
		struct ocf_alock_waiters_list *lst = &cncrrncy->waiters_lsts[idx]; \
		env_spinlock_unlock_irqrestore(&lst->lock, flags); \
	} while (0)


/*
 *
 */
static inline bool ocf_alock_trylock_entry_wr(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	env_atomic *access = &alock->access[line];
	int prev = env_atomic_cmpxchg(access, OCF_CACHE_LINE_ACCESS_IDLE,
			OCF_CACHE_LINE_ACCESS_WR);

	if (prev == OCF_CACHE_LINE_ACCESS_IDLE)
		return true;
	else
		return false;
}

/*
 *
 */
static inline bool ocf_alock_trylock_entry_rd_idle(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	env_atomic *access = &alock->access[line];
	int prev = env_atomic_cmpxchg(access, OCF_CACHE_LINE_ACCESS_IDLE,
			OCF_CACHE_LINE_ACCESS_ONE_RD);

	return (prev == OCF_CACHE_LINE_ACCESS_IDLE);
}

/*
 *
 */
static inline bool ocf_alock_trylock_entry_rd(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	env_atomic *access = &alock->access[line];

	return !!env_atomic_add_unless(access, 1, OCF_CACHE_LINE_ACCESS_WR);
}

/*
 *
 */
static inline void ocf_alock_unlock_entry_wr(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	env_atomic *access = &alock->access[line];

	ENV_BUG_ON(env_atomic_read(access) != OCF_CACHE_LINE_ACCESS_WR);
	env_atomic_set(access, OCF_CACHE_LINE_ACCESS_IDLE);
}

/*
 *
 */
static inline void ocf_alock_unlock_entry_rd(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	env_atomic *access = &alock->access[line];

	ENV_BUG_ON(env_atomic_read(access) == 0);
	ENV_BUG_ON(env_atomic_read(access) == OCF_CACHE_LINE_ACCESS_WR);
	env_atomic_dec(access);
}

/*
 *
 */
static inline
bool ocf_alock_trylock_entry_wr2wr(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	env_atomic *access = &alock->access[line];

	ENV_BUG_ON(env_atomic_read(access) != OCF_CACHE_LINE_ACCESS_WR);
	return true;
}

/*
 *
 */
static inline bool ocf_alock_trylock_entry_wr2rd(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	env_atomic *access = &alock->access[line];

	ENV_BUG_ON(env_atomic_read(access) != OCF_CACHE_LINE_ACCESS_WR);
	env_atomic_set(access, OCF_CACHE_LINE_ACCESS_ONE_RD);
	return true;
}

/*
 *
 */
static inline bool ocf_alock_trylock_entry_rd2wr(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	env_atomic *access = &alock->access[line];

	int v = env_atomic_read(access);

	ENV_BUG_ON(v == OCF_CACHE_LINE_ACCESS_IDLE);
	ENV_BUG_ON(v == OCF_CACHE_LINE_ACCESS_WR);

	v = env_atomic_cmpxchg(access, OCF_CACHE_LINE_ACCESS_ONE_RD,
			OCF_CACHE_LINE_ACCESS_WR);

	return (v == OCF_CACHE_LINE_ACCESS_ONE_RD);
}

/*
 *
 */
static inline bool ocf_alock_trylock_entry_rd2rd(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	env_atomic *access = &alock->access[line];

	int v = env_atomic_read(access);

	ENV_BUG_ON(v == OCF_CACHE_LINE_ACCESS_IDLE);
	ENV_BUG_ON(v == OCF_CACHE_LINE_ACCESS_WR);

	return true;
}

/*
 *
 */
static void ocf_alock_on_lock(struct ocf_alock *alock,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl)
{
	if (env_atomic_dec_return(&req->lock_remaining) == 0) {
		/* All cache line locked, resume request */
		OCF_DEBUG_RQ(req, "Resume");
		ENV_BUG_ON(!cmpl);
		env_atomic_dec(&alock->waiting);
		cmpl(req);
	}
}

/*
 *
 */
static inline bool ocf_alock_lock_one_wr(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t line, ocf_req_async_lock_cb cmpl,
		void *req, uint32_t idx)
{
	struct ocf_alock_waiter *waiter;
	bool waiting = false;
	unsigned long flags = 0;

	ENV_BUG_ON(!cmpl);

	if (ocf_alock_trylock_entry_wr(alock, line)) {
		/* lock was not owned by anyone */
		cbs->line_mark_locked(req, idx, OCF_WRITE, true);
		ocf_alock_on_lock(alock, req, cmpl);
		return true;
	}

	waiter = env_allocator_new(alock->allocator);
	if (!waiter)
		return false;

	ocf_alock_waitlist_lock(alock, line, flags);

	/* At the moment list is protected, double check if the cache line is
	 * unlocked
	 */
	if (ocf_alock_trylock_entry_wr(alock, line))
		goto unlock;

	/* Setup waiters filed */
	waiter->line = line;
	waiter->req = req;
	waiter->idx = idx;
	waiter->cmpl = cmpl;
	waiter->rw = OCF_WRITE;
	INIT_LIST_HEAD(&waiter->item);

	/* Add to waiters list */
	ocf_alock_waitlist_add(alock, line, waiter);
	waiting = true;

unlock:
	ocf_alock_waitlist_unlock(alock, line, flags);

	if (!waiting) {
		cbs->line_mark_locked(req, idx, OCF_WRITE, true);
		ocf_alock_on_lock(alock, req, cmpl);
		env_allocator_del(alock->allocator, waiter);
	}

	return true;
}

/*
 * Attempt to lock cache line for read.
 * In case cache line is locked,  attempt to add caller on wait list.
 */
static inline bool ocf_alock_lock_one_rd(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t line, ocf_req_async_lock_cb cmpl,
		void *req, uint32_t idx)
{
	struct ocf_alock_waiter *waiter;
	bool waiting = false;
	unsigned long flags = 0;

	ENV_BUG_ON(!cmpl);

	if( ocf_alock_trylock_entry_rd_idle(alock, line)) {
		/* lock was not owned by anyone */
		cbs->line_mark_locked(req, idx, OCF_READ, true);
		ocf_alock_on_lock(alock, req, cmpl);
		return true;
	}

	waiter = env_allocator_new(alock->allocator);
	if (!waiter)
		return false;

	/* Lock waiters list */
	ocf_alock_waitlist_lock(alock, line, flags);

	if (!ocf_alock_waitlist_are_waiters(alock, line)) {
		/* No waiters at the moment */

		/* Check if read lock can be obtained */
		if (ocf_alock_trylock_entry_rd(alock, line)) {
			/* Cache line locked */
			goto unlock;
		}
	}

	/* Setup waiters field */
	waiter->line = line;
	waiter->req = req;
	waiter->idx = idx;
	waiter->cmpl = cmpl;
	waiter->rw = OCF_READ;
	INIT_LIST_HEAD(&waiter->item);

	/* Add to waiters list */
	ocf_alock_waitlist_add(alock, line, waiter);
	waiting = true;

unlock:
	ocf_alock_waitlist_unlock(alock, line, flags);

	if (!waiting) {
		cbs->line_mark_locked(req, idx, OCF_READ, true);
		ocf_alock_on_lock(alock, req, cmpl);
		env_allocator_del(alock->allocator, waiter);
	}

	return true;
}

static inline void ocf_alock_unlock_one_rd_common(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t line)
{
	bool locked = false;
	bool exchanged = true;
	uint32_t i = 0;

	uint32_t idx = _WAITERS_LIST_ITEM(line);
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

		if (line != waiter->line)
			continue;

		if (exchanged) {
			if (waiter->rw == OCF_WRITE)
				locked = ocf_alock_trylock_entry_rd2wr(alock, line);
			else if (waiter->rw == OCF_READ)
				locked = ocf_alock_trylock_entry_rd2rd(alock, line);
			else
				ENV_BUG();
		} else {
			if (waiter->rw == OCF_WRITE)
				locked = ocf_alock_trylock_entry_wr(alock, line);
			else if (waiter->rw == OCF_READ)
				locked = ocf_alock_trylock_entry_rd(alock, line);
			else
				ENV_BUG();
		}

		i++;

		if (locked) {
			exchanged = false;
			list_del(iter);

			cbs->line_mark_locked(waiter->req, waiter->idx,
					waiter->rw, true);
			ocf_alock_on_lock(alock, waiter->req, waiter->cmpl);

			env_allocator_del(alock->allocator, waiter);
		} else {
			break;
		}
	}

	if (exchanged) {
		/* No exchange, no waiters on the list, unlock and return
		 * WR -> IDLE
		 */
		ocf_alock_unlock_entry_rd(alock, line);
	}
}

/*
 *
 */
static inline void ocf_alock_unlock_one_rd(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t line)
{
	unsigned long flags = 0;

	/* Lock waiters list */
	ocf_alock_waitlist_lock(alock, line, flags);
	ocf_alock_unlock_one_rd_common(alock, cbs, line);
	ocf_alock_waitlist_unlock(alock, line, flags);
}


static inline void ocf_alock_unlock_one_wr_common(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t line)
{
	uint32_t i = 0;
	bool locked = false;
	bool exchanged = true;

	uint32_t idx = _WAITERS_LIST_ITEM(line);
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

		if (line != waiter->line)
			continue;

		if (exchanged) {
			if (waiter->rw == OCF_WRITE)
				locked = ocf_alock_trylock_entry_wr2wr(alock, line);
			else if (waiter->rw == OCF_READ)
				locked = ocf_alock_trylock_entry_wr2rd(alock, line);
			else
				ENV_BUG();
		} else {
			if (waiter->rw == OCF_WRITE)
				locked = ocf_alock_trylock_entry_wr(alock, line);
			else if (waiter->rw == OCF_READ)
				locked = ocf_alock_trylock_entry_rd(alock, line);
			else
				ENV_BUG();
		}

		i++;

		if (locked) {
			exchanged = false;
			list_del(iter);

			cbs->line_mark_locked(waiter->req, waiter->idx,
					waiter->rw, true);
			ocf_alock_on_lock(alock, waiter->req, waiter->cmpl);

			env_allocator_del(alock->allocator, waiter);
		} else {
			break;
		}
	}

	if (exchanged) {
		/* No exchange, no waiters on the list, unlock and return
		 * WR -> IDLE
		 */
		ocf_alock_unlock_entry_wr(alock, line);
	}
}

/*
 *
 */
static inline void ocf_alock_unlock_one_wr(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		const ocf_cache_line_t line)
{
	unsigned long flags = 0;

	/* Lock waiters list */
	ocf_alock_waitlist_lock(alock, line, flags);
	ocf_alock_unlock_one_wr_common(alock, cbs, line);
	ocf_alock_waitlist_unlock(alock, line, flags);
}

/*
 * Safely remove cache line lock waiter from waiting list.
 * Request can be assigned with lock asynchronously at any point of time,
 * so need to check lock state under a common lock.
 */
static inline void ocf_alock_waitlist_remove_entry(struct ocf_alock *alock,
	struct ocf_alock_lock_cbs *cbs,
	struct ocf_request *req, int i, int rw)
{
	ocf_cache_line_t line = req->map[i].coll_idx;
	uint32_t idx = _WAITERS_LIST_ITEM(line);
	struct ocf_alock_waiters_list *lst = &alock->waiters_lsts[idx];
	struct list_head *iter, *next;
	struct ocf_alock_waiter *waiter;
	unsigned long flags = 0;

	ocf_alock_waitlist_lock(alock, line, flags);

	if (cbs->line_is_locked(req, i, rw)) {
		if (rw == OCF_READ)
			ocf_alock_unlock_one_rd_common(alock, cbs, line);
		else
			ocf_alock_unlock_one_wr_common(alock, cbs, line);
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

	ocf_alock_waitlist_unlock(alock, line, flags);
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
	ocf_cache_line_t line;
	int ret = OCF_LOCK_ACQUIRED;

	OCF_DEBUG_RQ(req, "Lock");

	ENV_BUG_ON(env_atomic_read(&req->lock_remaining));

	for (i = 0; i < req->core_line_count; i++) {
		if (!cbs->line_needs_lock(req, i)) {
			/* nothing to lock */
			continue;
		}

		line = req->map[i].coll_idx;
		ENV_BUG_ON(line >= alock->num_clines);
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_READ));
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_WRITE));

		if( ocf_alock_trylock_entry_rd_idle(alock, line)) {
			/* cache line locked */
			cbs->line_mark_locked(req, i, OCF_READ, true);
		} else {
			/* Not possible to lock all cachelines */
			ret = OCF_LOCK_NOT_ACQUIRED;
			OCF_DEBUG_RQ(req, "NO Lock, cache line = %u", line);
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

			line = req->map[i].coll_idx;

			if (cbs->line_is_locked(req, i, OCF_READ)) {
				ocf_alock_unlock_one_rd(alock, cbs, line);
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
	ocf_cache_line_t line;
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

		line = req->map[i].coll_idx;
		ENV_BUG_ON(line >= alock->num_clines);
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_READ));
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_WRITE));

		if (!ocf_alock_lock_one_rd(alock, cbs, line, cmpl, req, i)) {
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

static int ocf_alock_lock_rd(struct ocf_alock *alock,
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

int ocf_req_async_lock_rd(struct ocf_alock *alock,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	return ocf_alock_lock_rd(alock, cbs, req, cmpl);
}

/* Try to write-lock request without adding waiters. Function should be called
 * under read lock, multiple threads may attempt to acquire the lock
 * concurrently. */
static int ocf_alock_lock_wr_fast(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req)
{
	int32_t i;
	ocf_cache_line_t line;
	int ret = OCF_LOCK_ACQUIRED;

	ENV_BUG_ON(env_atomic_read(&req->lock_remaining));

	for (i = 0; i < req->core_line_count; i++) {
		if (!cbs->line_needs_lock(req, i)) {
			/* nothing to lock */
			continue;
		}

		line = req->map[i].coll_idx;
		ENV_BUG_ON(line >= alock->num_clines);
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_READ));
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_WRITE));

		if (ocf_alock_trylock_entry_wr(alock, line)) {
			/* cache line locked */
			cbs->line_mark_locked(req, i, OCF_WRITE, true);
		} else {
			/* Not possible to lock all cachelines */
			ret = OCF_LOCK_NOT_ACQUIRED;
			OCF_DEBUG_RQ(req, "NO Lock, cache line = %u", line);
			break;
		}
	}

	/* Check if request is locked */
	if (ret == OCF_LOCK_NOT_ACQUIRED) {
		/* Request is not locked, discard acquired locks */
		for (; i >= 0; i--) {
			if (!cbs->line_needs_lock(req, i))
				continue;

			line = req->map[i].coll_idx;

			if (cbs->line_is_locked(req, i, OCF_WRITE)) {
				ocf_alock_unlock_one_wr(alock, cbs, line);
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
	ocf_cache_line_t line;
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

		line = req->map[i].coll_idx;
		ENV_BUG_ON(line >= alock->num_clines);
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_READ));
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_WRITE));

		if (!ocf_alock_lock_one_wr(alock, cbs, line, cmpl, req, i)) {
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

int ocf_req_async_lock_wr(struct ocf_alock *alock,
		struct ocf_request *req, ocf_req_async_lock_cb cmpl)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	return ocf_alock_lock_wr(alock, cbs, req, cmpl);
}

/*
 *
 */
void ocf_alock_unlock_rd(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req)
{
	int32_t i;
	ocf_cache_line_t line;

	OCF_DEBUG_RQ(req, "Unlock");

	for (i = 0; i < req->core_line_count; i++) {
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_WRITE));

		if (!cbs->line_is_acting(req, i))
			continue;

		if (!cbs->line_is_locked(req, i, OCF_READ))
			continue;

		line = req->map[i].coll_idx;

		ENV_BUG_ON(line >= alock->num_clines);

		ocf_alock_unlock_one_rd(alock, cbs, line);
		cbs->line_mark_locked(req, i, OCF_READ, false);
	}
}

void ocf_req_unlock_rd(struct ocf_alock *alock, struct ocf_request *req)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	ocf_alock_unlock_rd(alock, cbs, req);
}

/*
 *
 */
void ocf_alock_unlock_wr(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req)
{
	int32_t i;
	ocf_cache_line_t line;

	OCF_DEBUG_RQ(req, "Unlock");

	for (i = 0; i < req->core_line_count; i++) {
		ENV_BUG_ON(cbs->line_is_locked(req, i, OCF_READ));

		if (!cbs->line_is_acting(req, i))
			continue;

		if (!cbs->line_is_locked(req, i, OCF_WRITE))
			continue;

		line = req->map[i].coll_idx;

		ENV_BUG_ON(line >= alock->num_clines);

		ocf_alock_unlock_one_wr(alock, cbs, line);
		cbs->line_mark_locked(req, i, OCF_WRITE, false);
	}
}

void ocf_req_unlock_wr(struct ocf_alock *alock, struct ocf_request *req)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	ocf_alock_unlock_wr(alock, cbs, req);
}

/*
 *
 */
void ocf_alock_unlock(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req)
{
	int32_t i;
	ocf_cache_line_t line;

	OCF_DEBUG_RQ(req, "Unlock");

	for (i = 0; i < req->core_line_count; i++) {
		if (!cbs->line_is_acting(req, i))
			continue;

		line = req->map[i].coll_idx;
		ENV_BUG_ON(line >= alock->num_clines);

		if (cbs->line_is_locked(req, i, OCF_READ) &&
				cbs->line_is_locked(req, i, OCF_WRITE)) {
			ENV_BUG();
		} else if (cbs->line_is_locked(req, i, OCF_READ)) {
			ocf_alock_unlock_one_rd(alock, cbs, line);
			cbs->line_mark_locked(req, i, OCF_READ, false);
		} else if (cbs->line_is_locked(req, i, OCF_WRITE)) {
			ocf_alock_unlock_one_wr(alock, cbs, line);
			cbs->line_mark_locked(req, i, OCF_WRITE, false);
		}
	}
}

void ocf_req_unlock(struct ocf_alock *alock, struct ocf_request *req)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	ocf_alock_unlock(alock, cbs, req);
}

/*
 *
 */
void ocf_alock_unlock_one(struct ocf_alock *alock,
		struct ocf_alock_lock_cbs *cbs,
		struct ocf_request *req, uint32_t entry)
{
	ENV_BUG_ON(!cbs->line_is_acting(req, entry));

	if (cbs->line_is_locked(req, entry, OCF_READ) &&
			cbs->line_is_locked(req, entry, OCF_WRITE)) {
		ENV_BUG();
	} else if (cbs->line_is_locked(req, entry, OCF_READ)) {
		ocf_alock_unlock_one_rd(alock, cbs, req->map[entry].coll_idx);
		cbs->line_mark_locked(req, entry, OCF_READ, false);
	} else if (cbs->line_is_locked(req, entry, OCF_WRITE)) {
		ocf_alock_unlock_one_wr(alock, cbs, req->map[entry].coll_idx);
		cbs->line_mark_locked(req, entry, OCF_WRITE, false);
	} else {
		ENV_BUG();
	}
}

void ocf_req_unlock_entry(struct ocf_alock *alock,
		struct ocf_request *req, uint32_t entry)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	ocf_alock_unlock_one(alock, cbs, req, entry);
}

/*
 *
 */
bool ocf_cache_line_is_used(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	ENV_BUG_ON(line >= alock->num_clines);

	if (env_atomic_read(&(alock->access[line])))
		return true;

	if (ocf_cache_line_are_waiters(alock, line))
		return true;
	else
		return false;
}

/*
 *
 */
bool ocf_cache_line_are_waiters(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	bool are;
	unsigned long flags = 0;

	ENV_BUG_ON(line >= alock->num_clines);

	/* Lock waiters list */
	ocf_alock_waitlist_lock(alock, line, flags);

	are = ocf_alock_waitlist_are_waiters(alock, line);

	ocf_alock_waitlist_unlock(alock, line, flags);

	return are;
}

/* NOTE: it is caller responsibility to assure that noone acquires
 * a lock in background */
bool ocf_cache_line_is_locked_exclusively(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	struct ocf_alock *alock =
			ocf_cache_line_concurrency(cache);
	env_atomic *access = &alock->access[line];
	int val = env_atomic_read(access);

	ENV_BUG_ON(val == OCF_CACHE_LINE_ACCESS_IDLE);

	if (ocf_cache_line_are_waiters(alock, line))
		return false;

	return val == OCF_CACHE_LINE_ACCESS_ONE_RD ||
			val == OCF_CACHE_LINE_ACCESS_WR;
}

/*
 *
 */
uint32_t ocf_cache_line_concurrency_suspended_no(struct ocf_alock *alock)
{
	return env_atomic_read(&alock->waiting);
}

bool ocf_cache_line_try_lock_rd(struct ocf_alock *alock,
		ocf_cache_line_t line)
{
	return ocf_alock_trylock_entry_rd_idle(alock, line);
}

/*
 *
 */
void ocf_cache_line_unlock_rd(struct ocf_alock *alock, ocf_cache_line_t line)
{
	struct ocf_alock_lock_cbs *cbs =
			&ocf_cline_conc_cbs;

	OCF_DEBUG_RQ(alock->cache, "Cache line = %u", line);
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

	OCF_DEBUG_RQ(alock->cache, "Cache line = %u", line);
	ocf_alock_unlock_one_wr(alock, cbs, line);
}
