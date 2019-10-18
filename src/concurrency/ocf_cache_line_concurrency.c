/*
 * Copyright(c) 2012-2018 Intel Corporation
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
	(_WAITERS_LIST_SIZE / sizeof(struct __waiters_list))

#define _WAITERS_LIST_ITEM(cache_line) ((cache_line) % _WAITERS_LIST_ENTRIES)

struct __waiter {
	ocf_cache_line_t line;
	void *ctx;
	uint32_t ctx_id;
	ocf_req_async_lock_cb cb;
	struct list_head item;
	int rw;
};

struct __waiters_list {
	struct list_head head;
	env_spinlock lock;
};

struct ocf_cache_line_concurrency {
	env_rwsem lock;
	env_atomic *access;
	env_atomic waiting;
	size_t access_limit;
	env_allocator *allocator;
	struct __waiters_list waiters_lsts[_WAITERS_LIST_ENTRIES];

};

/*
 *
 */

#define ALLOCATOR_NAME_FMT "ocf_%s_cache_concurrency"
#define ALLOCATOR_NAME_MAX (sizeof(ALLOCATOR_NAME_FMT) + OCF_CACHE_NAME_SIZE)

int ocf_cache_line_concurrency_init(struct ocf_cache *cache)
{
	uint32_t i;
	int error = 0;
	struct ocf_cache_line_concurrency *c;
	char name[ALLOCATOR_NAME_MAX];
	ocf_cache_line_t line_entries = ocf_metadata_collision_table_entries(
						cache);

	ENV_BUG_ON(cache->device->concurrency.cache_line);

	OCF_DEBUG_TRACE(cache);

	c = env_vmalloc(sizeof(*c));
	if (!c) {
		error = __LINE__;
		goto ocf_cache_line_concurrency_init;
	}

	error = env_rwsem_init(&c->lock);
	if (error) {
		env_vfree(c);
		error = __LINE__;
		goto ocf_cache_line_concurrency_init;
	}

	cache->device->concurrency.cache_line = c;

	OCF_REALLOC_INIT(&c->access, &c->access_limit);
	OCF_REALLOC_CP(&c->access, sizeof(c->access[0]), line_entries,
		&c->access_limit);

	if (!c->access) {
		error = __LINE__;
		goto ocf_cache_line_concurrency_init;
	}

	if (snprintf(name, sizeof(name), ALLOCATOR_NAME_FMT,
			ocf_cache_get_name(cache)) < 0) {
		error = __LINE__;
		goto ocf_cache_line_concurrency_init;
	}

	c->allocator = env_allocator_create(sizeof(struct __waiter), name);
	if (!c->allocator) {
		error = __LINE__;
		goto ocf_cache_line_concurrency_init;
	}

	/* Init concurrency control table */
	for (i = 0; i < _WAITERS_LIST_ENTRIES; i++) {
		INIT_LIST_HEAD(&c->waiters_lsts[i].head);
		error = env_spinlock_init(&c->waiters_lsts[i].lock);
		if (error)
			goto spinlock_err;
	}

	return 0;

spinlock_err:
	while (i--)
		env_spinlock_destroy(&c->waiters_lsts[i].lock);
ocf_cache_line_concurrency_init:
	ocf_cache_log(cache, log_err, "Cannot initialize cache concurrency, "
			"ERROR %d", error);

	if (cache->device->concurrency.cache_line)
		ocf_cache_line_concurrency_deinit(cache);

	return -1;
}

/*
 *
 */
void ocf_cache_line_concurrency_deinit(struct ocf_cache *cache)
{
	int i;
	struct ocf_cache_line_concurrency *concurrency;

	if (!cache->device->concurrency.cache_line)
		return;

	OCF_DEBUG_TRACE(cache);

	concurrency = cache->device->concurrency.cache_line;

	env_rwsem_destroy(&concurrency->lock);

	for (i = 0; i < _WAITERS_LIST_ENTRIES; i++)
		env_spinlock_destroy(&concurrency->waiters_lsts[i].lock);

	if (concurrency->access)
		OCF_REALLOC_DEINIT(&concurrency->access,
				&concurrency->access_limit);

	if (concurrency->allocator)
		env_allocator_destroy(concurrency->allocator);

	env_vfree(concurrency);
	cache->device->concurrency.cache_line = NULL;
}

size_t ocf_cache_line_concurrency_size_of(struct ocf_cache *cache)
{
	size_t size;

	size = sizeof(env_atomic);
	size *= cache->device->collision_table_entries;

	size += sizeof(struct ocf_cache_line_concurrency);

	return size;
}

/*
 *
 */
static inline bool __are_waiters(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line)
{
	bool are = false;
	struct list_head *iter;
	uint32_t idx = _WAITERS_LIST_ITEM(line);
	struct __waiters_list *lst = &c->waiters_lsts[idx];
	struct __waiter *waiter;

	/* If list empty that means there are no waiters on cache line */
	if (list_empty(&lst->head))
		return false;

	list_for_each(iter, &lst->head) {
		waiter = list_entry(iter, struct __waiter, item);

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
static inline void __add_waiter(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line, struct __waiter *waiter)
{
	uint32_t idx = _WAITERS_LIST_ITEM(line);
	struct __waiters_list *lst = &c->waiters_lsts[idx];

	list_add_tail(&waiter->item, &lst->head);
}


#define __lock_waiters_list(cncrrncy, line, flags) \
	do { \
		uint32_t idx = _WAITERS_LIST_ITEM(line); \
		struct __waiters_list *lst = &cncrrncy->waiters_lsts[idx]; \
		env_spinlock_lock_irqsave(&lst->lock, flags); \
	} while (0)

#define __unlock_waiters_list(cncrrncy, line, flags) \
	do { \
		uint32_t idx = _WAITERS_LIST_ITEM(line); \
		struct __waiters_list *lst = &cncrrncy->waiters_lsts[idx]; \
		env_spinlock_unlock_irqrestore(&lst->lock, flags); \
	} while (0)


/*
 *
 */
static inline bool __try_lock_wr(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line)
{
	env_atomic *access = &c->access[line];
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
static inline bool __try_lock_rd_idle(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line)
{
	env_atomic *access = &c->access[line];
	int prev = env_atomic_cmpxchg(access, OCF_CACHE_LINE_ACCESS_IDLE,
			OCF_CACHE_LINE_ACCESS_ONE_RD);

	return (prev == OCF_CACHE_LINE_ACCESS_IDLE);
}

/*
 *
 */
static inline bool __try_lock_rd(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line)
{
	env_atomic *access = &c->access[line];

	return !!env_atomic_add_unless(access, 1, OCF_CACHE_LINE_ACCESS_WR);
}

/*
 *
 */
static inline void __unlock_wr(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line)
{
	env_atomic *access = &c->access[line];

	ENV_BUG_ON(env_atomic_read(access) != OCF_CACHE_LINE_ACCESS_WR);
	env_atomic_set(access, OCF_CACHE_LINE_ACCESS_IDLE);
}

/*
 *
 */
static inline void __unlock_rd(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line)
{
	env_atomic *access = &c->access[line];

	ENV_BUG_ON(env_atomic_read(access) == 0);
	ENV_BUG_ON(env_atomic_read(access) == OCF_CACHE_LINE_ACCESS_WR);
	env_atomic_dec(access);
}

/*
 *
 */
static inline bool __try_lock_wr2wr(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line)
{
	env_atomic *access = &c->access[line];

	ENV_BUG_ON(env_atomic_read(access) != OCF_CACHE_LINE_ACCESS_WR);
	return true;
}

/*
 *
 */
static inline bool __try_lock_wr2rd(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line)
{
	env_atomic *access = &c->access[line];

	ENV_BUG_ON(env_atomic_read(access) != OCF_CACHE_LINE_ACCESS_WR);
	env_atomic_set(access, OCF_CACHE_LINE_ACCESS_ONE_RD);
	return true;
}

/*
 *
 */
static inline bool __try_lock_rd2wr(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line)
{
	env_atomic *access = &c->access[line];

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
static inline bool __try_lock_rd2rd(struct ocf_cache_line_concurrency *c,
		ocf_cache_line_t line)
{
	env_atomic *access = &c->access[line];

	int v = env_atomic_read(access);

	ENV_BUG_ON(v == OCF_CACHE_LINE_ACCESS_IDLE);
	ENV_BUG_ON(v == OCF_CACHE_LINE_ACCESS_WR);

	return true;
}

/*
 *
 */
static void _req_on_lock(void *ctx, ocf_req_async_lock_cb cb,
		uint32_t ctx_id, ocf_cache_line_t line, int rw)
{
	struct ocf_request *req = ctx;
	struct ocf_cache_line_concurrency *c = req->cache->device->concurrency.
			cache_line;

	if (rw == OCF_READ)
		req->map[ctx_id].rd_locked = true;
	else if (rw == OCF_WRITE)
		req->map[ctx_id].wr_locked = true;
	else
		ENV_BUG();

	if (env_atomic_dec_return(&req->lock_remaining) == 0) {
		/* All cache line locked, resume request */
		OCF_DEBUG_RQ(req, "Resume");
		ENV_BUG_ON(!cb);
		env_atomic_dec(&c->waiting);
		cb(req);
	}
}

/*
 *
 */
static inline bool __lock_cache_line_wr(struct ocf_cache_line_concurrency *c,
		const ocf_cache_line_t line, ocf_req_async_lock_cb cb,
		void *ctx, uint32_t ctx_id)
{
	struct __waiter *waiter;
	bool locked = false;
	bool waiting = false;
	unsigned long flags = 0;

	if (__try_lock_wr(c, line)) {
		/* No activity before look get */
		if (cb)
			_req_on_lock(ctx, cb, ctx_id, line, OCF_WRITE);
		return true;
	}

	waiter = NULL;
	if (cb) {
		/* Need to create waiter */
		waiter = env_allocator_new(c->allocator);
		if (!waiter)
			return false;
	}

	__lock_waiters_list(c, line, flags);

	/* At the moment list is protected, double check if the cache line is
	 * unlocked
	 */
	if (__try_lock_wr(c, line)) {
		/* Look get */
		locked = true;
	} else if (cb) {
		/* Setup waiters filed */
		waiter->line = line;
		waiter->ctx = ctx;
		waiter->ctx_id = ctx_id;
		waiter->cb = cb;
		waiter->rw = OCF_WRITE;
		INIT_LIST_HEAD(&waiter->item);

		/* Add to waiters list */
		__add_waiter(c, line, waiter);
		waiting = true;
	}

	__unlock_waiters_list(c, line, flags);

	if (locked && cb)
		_req_on_lock(ctx, cb, ctx_id, line, OCF_WRITE);
	if (!waiting && waiter)
		env_allocator_del(c->allocator, waiter);

	return locked || waiting;
}

/*
 * Attempt to lock cache line for read.
 * In case cache line is locked,  attempt to add caller on wait list.
 */
static inline bool __lock_cache_line_rd(struct ocf_cache_line_concurrency *c,
		const ocf_cache_line_t line, ocf_req_async_lock_cb cb,
		void *ctx, uint32_t ctx_id)
{
	struct __waiter *waiter;
	bool locked = false;
	bool waiting = false;
	unsigned long flags = 0;

	if (__try_lock_rd_idle(c, line)) {
		/* No activity before look get, it is first reader */
		if (cb)
			_req_on_lock(ctx, cb, ctx_id, line, OCF_READ);
		return true;
	}

	waiter = NULL;

repeat:
	/* Lock waiters list */
	__lock_waiters_list(c, line, flags);

	if (!__are_waiters(c, line)) {
		/* No waiters at the moment */

		/* Check if read lock can be obtained */
		if (__try_lock_rd(c, line)) {
			/* Cache line locked */
			locked = true;
			goto unlock;
		}
	}

	if (!cb)
		goto unlock;

	if (!waiter) {
		/* Need to create waiters and add it into list */
		__unlock_waiters_list(c, line, flags);
		waiter = env_allocator_new(c->allocator);
		if (!waiter)
			goto end;
		goto repeat;
	}

	/* Setup waiters field */
	waiter->line = line;
	waiter->ctx = ctx;
	waiter->ctx_id = ctx_id;
	waiter->cb = cb;
	waiter->rw = OCF_READ;
	INIT_LIST_HEAD(&waiter->item);

	/* Add to waiters list */
	__add_waiter(c, line, waiter);
	waiting = true;

unlock:
	__unlock_waiters_list(c, line, flags);

end:
	if (locked && cb)
		_req_on_lock(ctx, cb, ctx_id, line, OCF_READ);
	if (!waiting && waiter)
		env_allocator_del(c->allocator, waiter);

	return locked || waiting;
}

static inline void __unlock_cache_line_rd_common(struct ocf_cache_line_concurrency *c,
		const ocf_cache_line_t line)
{
	bool locked = false;
	bool exchanged = true;
	uint32_t i = 0;

	uint32_t idx = _WAITERS_LIST_ITEM(line);
	struct __waiters_list *lst = &c->waiters_lsts[idx];
	struct __waiter *waiter;

	struct list_head *iter, *next;

	/*
	 * Lock exchange scenario
	 * 1. RD -> IDLE
	 * 2. RD -> RD
	 * 3. RD -> WR
	 */

	/* Check is requested page is on the list */
	list_for_each_safe(iter, next, &lst->head) {
		waiter = list_entry(iter, struct __waiter, item);

		if (line != waiter->line)
			continue;

		if (exchanged) {
			if (waiter->rw == OCF_WRITE)
				locked = __try_lock_rd2wr(c, line);
			else if (waiter->rw == OCF_READ)
				locked = __try_lock_rd2rd(c, line);
			else
				ENV_BUG();
		} else {
			if (waiter->rw == OCF_WRITE)
				locked = __try_lock_wr(c, line);
			else if (waiter->rw == OCF_READ)
				locked = __try_lock_rd(c, line);
			else
				ENV_BUG();
		}

		i++;

		if (locked) {
			exchanged = false;
			list_del(iter);

			_req_on_lock(waiter->ctx, waiter->cb, waiter->ctx_id,
					line, waiter->rw);

			env_allocator_del(c->allocator, waiter);
		} else {
			break;
		}
	}

	if (exchanged) {
		/* No exchange, no waiters on the list, unlock and return
		 * WR -> IDLE
		 */
		__unlock_rd(c, line);
	}
}

/*
 *
 */
static inline void __unlock_cache_line_rd(struct ocf_cache_line_concurrency *c,
		const ocf_cache_line_t line)
{
	unsigned long flags = 0;

	/* Lock waiters list */
	__lock_waiters_list(c, line, flags);
	__unlock_cache_line_rd_common(c, line);
	__unlock_waiters_list(c, line, flags);
}


static inline void __unlock_cache_line_wr_common(struct ocf_cache_line_concurrency *c,
		const ocf_cache_line_t line)
{
	uint32_t i = 0;
	bool locked = false;
	bool exchanged = true;

	uint32_t idx = _WAITERS_LIST_ITEM(line);
	struct __waiters_list *lst = &c->waiters_lsts[idx];
	struct __waiter *waiter;

	struct list_head *iter, *next;

	/*
	 * Lock exchange scenario
	 * 1. WR -> IDLE
	 * 2. WR -> RD
	 * 3. WR -> WR
	 */

	/* Check is requested page is on the list */
	list_for_each_safe(iter, next, &lst->head) {
		waiter = list_entry(iter, struct __waiter, item);

		if (line != waiter->line)
			continue;

		if (exchanged) {
			if (waiter->rw == OCF_WRITE)
				locked = __try_lock_wr2wr(c, line);
			else if (waiter->rw == OCF_READ)
				locked = __try_lock_wr2rd(c, line);
			else
				ENV_BUG();
		} else {
			if (waiter->rw == OCF_WRITE)
				locked = __try_lock_wr(c, line);
			else if (waiter->rw == OCF_READ)
				locked = __try_lock_rd(c, line);
			else
				ENV_BUG();
		}

		i++;

		if (locked) {
			exchanged = false;
			list_del(iter);

			_req_on_lock(waiter->ctx, waiter->cb, waiter->ctx_id, line,
					waiter->rw);

			env_allocator_del(c->allocator, waiter);
		} else {
			break;
		}
	}

	if (exchanged) {
		/* No exchange, no waiters on the list, unlock and return
		 * WR -> IDLE
		 */
		__unlock_wr(c, line);
	}
}

/*
 *
 */
static inline void __unlock_cache_line_wr(struct ocf_cache_line_concurrency *c,
		const ocf_cache_line_t line)
{
	unsigned long flags = 0;

	/* Lock waiters list */
	__lock_waiters_list(c, line, flags);
	__unlock_cache_line_wr_common(c, line);
	__unlock_waiters_list(c, line, flags);
}

/*
 * Safely remove cache line lock waiter from waiting list.
 * Request can be assigned with lock asynchronously at any point of time,
 * so need to check lock state under a common lock.
 */
static inline void __remove_line_from_waiters_list(struct ocf_cache_line_concurrency *c,
	struct ocf_request *req, int i, void *ctx, int rw)
{
	ocf_cache_line_t line = req->map[i].coll_idx;
	uint32_t idx = _WAITERS_LIST_ITEM(line);
	struct __waiters_list *lst = &c->waiters_lsts[idx];
	struct list_head *iter, *next;
	struct __waiter *waiter;
	unsigned long flags = 0;

	__lock_waiters_list(c, line, flags);

	if (rw == OCF_READ && req->map[i].rd_locked) {
		__unlock_cache_line_rd_common(c, line);
		req->map[i].rd_locked = false;
	} else if (rw == OCF_WRITE && req->map[i].wr_locked) {
		__unlock_cache_line_wr_common(c, line);
		req->map[i].wr_locked = false;
	} else {
		list_for_each_safe(iter, next, &lst->head) {
			waiter = list_entry(iter, struct __waiter, item);
			if (waiter->ctx == ctx) {
				list_del(iter);
				env_allocator_del(c->allocator, waiter);
			}
		}
	}

	__unlock_waiters_list(c, line, flags);
}

/* Try to read-lock request without adding waiters. Function should be called
 * under read lock, multiple threads may attempt to acquire the lock
 * concurrently. */
static int _ocf_req_trylock_rd(struct ocf_request *req)
{
	int32_t i;
	struct ocf_cache_line_concurrency *c = req->cache->device->concurrency.
			cache_line;
	ocf_cache_line_t line;
	int ret = OCF_LOCK_ACQUIRED;

	OCF_DEBUG_RQ(req, "Lock");

	ENV_BUG_ON(env_atomic_read(&req->lock_remaining));

	for (i = 0; i < req->core_line_count; i++) {
		if (req->map[i].status == LOOKUP_MISS) {
			/* MISS nothing to lock */
			continue;
		}

		line = req->map[i].coll_idx;
		ENV_BUG_ON(line >= req->cache->device->collision_table_entries);
		ENV_BUG_ON(req->map[i].rd_locked);
		ENV_BUG_ON(req->map[i].wr_locked);

		if (__lock_cache_line_rd(c, line, NULL, NULL, 0)) {
			/* cache line locked */
			req->map[i].rd_locked = true;
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
			line = req->map[i].coll_idx;

			if (req->map[i].rd_locked) {
				__unlock_rd(c, line);
				req->map[i].rd_locked = false;
			}
		}
	}

	return ret;
}

/*
 * Read-lock request cache lines. Must be called under cacheline concurrency
 * write lock.
 */
static int _ocf_req_lock_rd(struct ocf_request *req, ocf_req_async_lock_cb cb)
{
	int32_t i;
	struct ocf_cache_line_concurrency *c = req->cache->device->concurrency.
			cache_line;
	ocf_cache_line_t line;
	int ret = OCF_LOCK_NOT_ACQUIRED;

	ENV_BUG_ON(env_atomic_read(&req->lock_remaining));

	env_atomic_inc(&c->waiting);
	env_atomic_set(&req->lock_remaining, req->core_line_count);
	env_atomic_inc(&req->lock_remaining);

	for (i = 0; i < req->core_line_count; i++) {

		if (req->map[i].status == LOOKUP_MISS) {
			/* MISS nothing to lock */
			env_atomic_dec(&req->lock_remaining);
			continue;
		}

		line = req->map[i].coll_idx;
		ENV_BUG_ON(line >= req->cache->device->collision_table_entries);
		ENV_BUG_ON(req->map[i].rd_locked);
		ENV_BUG_ON(req->map[i].wr_locked);

		if (!__lock_cache_line_rd(c, line, cb, req, i)) {
			/* lock not acquired and not added to wait list */
			ret = -OCF_ERR_NO_MEM;
			goto err;
		}
	}

	if (env_atomic_dec_return(&req->lock_remaining) == 0) {
		ret = OCF_LOCK_ACQUIRED;
		env_atomic_dec(&c->waiting);
	}

	return ret;

err:
	for (; i >= 0; i--) {
		__remove_line_from_waiters_list(c, req, i, req,
				OCF_READ);
	}
	env_atomic_set(&req->lock_remaining, 0);
	env_atomic_dec(&c->waiting);

	return ret;

}

int ocf_req_async_lock_rd(struct ocf_request *req, ocf_req_async_lock_cb cb)
{
	struct ocf_cache_line_concurrency *c =
		req->cache->device->concurrency.cache_line;
	int lock;

	env_rwsem_down_read(&c->lock);
	lock = _ocf_req_trylock_rd(req);
	env_rwsem_up_read(&c->lock);

	if (lock != OCF_LOCK_ACQUIRED) {
		env_rwsem_down_write(&c->lock);
		lock = _ocf_req_lock_rd(req, cb);
		env_rwsem_up_write(&c->lock);
	}

	return lock;
}

/* Try to write-lock request without adding waiters. Function should be called
 * under read lock, multiple threads may attempt to acquire the lock
 * concurrently. */
static int _ocf_req_trylock_wr(struct ocf_request *req)
{
	int32_t i;
	struct ocf_cache_line_concurrency *c = req->cache->device->concurrency.
			cache_line;
	ocf_cache_line_t line;
	int ret = OCF_LOCK_ACQUIRED;

	ENV_BUG_ON(env_atomic_read(&req->lock_remaining));

	for (i = 0; i < req->core_line_count; i++) {
		if (req->map[i].status == LOOKUP_MISS) {
			/* MISS nothing to lock */
			continue;
		}

		line = req->map[i].coll_idx;
		ENV_BUG_ON(line >= req->cache->device->collision_table_entries);
		ENV_BUG_ON(req->map[i].rd_locked);
		ENV_BUG_ON(req->map[i].wr_locked);

		if (__lock_cache_line_wr(c, line, NULL, NULL, 0)) {
			/* cache line locked */
			req->map[i].wr_locked = true;
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
			line = req->map[i].coll_idx;

			if (req->map[i].wr_locked) {
				__unlock_wr(c, line);
				req->map[i].wr_locked = false;
			}
		}
	}

	return ret;
}

/*
 * Write-lock request cache lines. Must be called under cacheline concurrency
 * write lock.
 */
static int _ocf_req_lock_wr(struct ocf_request *req, ocf_req_async_lock_cb cb)
{
	int32_t i;
	struct ocf_cache_line_concurrency *c = req->cache->device->concurrency.
			cache_line;
	ocf_cache_line_t line;
	int ret = OCF_LOCK_NOT_ACQUIRED;

	ENV_BUG_ON(env_atomic_read(&req->lock_remaining));
	ENV_BUG_ON(!cb);

	env_atomic_inc(&c->waiting);
	env_atomic_set(&req->lock_remaining, req->core_line_count);
	env_atomic_inc(&req->lock_remaining);

	for (i = 0; i < req->core_line_count; i++) {

		if (req->map[i].status == LOOKUP_MISS) {
			/* MISS nothing to lock */
			env_atomic_dec(&req->lock_remaining);
			continue;
		}

		line = req->map[i].coll_idx;
		ENV_BUG_ON(line >= req->cache->device->collision_table_entries);
		ENV_BUG_ON(req->map[i].rd_locked);
		ENV_BUG_ON(req->map[i].wr_locked);

		if (!__lock_cache_line_wr(c, line, cb, req, i)) {
			/* lock not acquired and not added to wait list */
			ret = -OCF_ERR_NO_MEM;
			goto err;
		}
	}

	if (env_atomic_dec_return(&req->lock_remaining) == 0) {
		ret = OCF_LOCK_ACQUIRED;
		env_atomic_dec(&c->waiting);
	}

	return ret;

err:
	for (; i >= 0; i--) {
		__remove_line_from_waiters_list(c, req, i, req,
				OCF_WRITE);
	}
	env_atomic_set(&req->lock_remaining, 0);
	env_atomic_dec(&c->waiting);

	return ret;
}

int ocf_req_async_lock_wr(struct ocf_request *req, ocf_req_async_lock_cb cb)
{
	struct ocf_cache_line_concurrency *c =
		req->cache->device->concurrency.cache_line;
	int lock;

	env_rwsem_down_read(&c->lock);
	lock = _ocf_req_trylock_wr(req);
	env_rwsem_up_read(&c->lock);

	if (lock != OCF_LOCK_ACQUIRED) {
		env_rwsem_down_write(&c->lock);
		lock = _ocf_req_lock_wr(req, cb);
		env_rwsem_up_write(&c->lock);
	}

	return lock;
}


/*
 *
 */
void ocf_req_unlock_rd(struct ocf_request *req)
{
	struct ocf_cache_line_concurrency *c = req->cache->device->concurrency.cache_line;
	int32_t i;
	ocf_cache_line_t line;

	OCF_DEBUG_RQ(req, "Unlock");

	for (i = 0; i < req->core_line_count; i++) {

		if (req->map[i].status == LOOKUP_MISS) {
			/* MISS nothing to lock */
			continue;
		}

		line = req->map[i].coll_idx;

		ENV_BUG_ON(!req->map[i].rd_locked);
		ENV_BUG_ON(line >= req->cache->device->collision_table_entries);

		__unlock_cache_line_rd(c, line);
		req->map[i].rd_locked = false;
	}
}

/*
 *
 */
void ocf_req_unlock_wr(struct ocf_request *req)
{
	struct ocf_cache_line_concurrency *c = req->cache->device->concurrency.cache_line;
	int32_t i;
	ocf_cache_line_t line;

	OCF_DEBUG_RQ(req, "Unlock");

	for (i = 0; i < req->core_line_count; i++) {

		if (req->map[i].status == LOOKUP_MISS) {
			/* MISS nothing to lock */
			continue;
		}

		line = req->map[i].coll_idx;

		ENV_BUG_ON(!req->map[i].wr_locked);
		ENV_BUG_ON(line >= req->cache->device->collision_table_entries);

		__unlock_cache_line_wr(c, line);
		req->map[i].wr_locked = false;
	}
}

/*
 *
 */
void ocf_req_unlock(struct ocf_request *req)
{
	struct ocf_cache_line_concurrency *c = req->cache->device->concurrency.cache_line;
	int32_t i;
	ocf_cache_line_t line;

	OCF_DEBUG_RQ(req, "Unlock");

	for (i = 0; i < req->core_line_count; i++) {

		if (req->map[i].status == LOOKUP_MISS) {
			/* MISS nothing to lock */
			continue;
		}

		line = req->map[i].coll_idx;
		ENV_BUG_ON(line >= req->cache->device->collision_table_entries);

		if (req->map[i].rd_locked && req->map[i].wr_locked) {
			ENV_BUG();
		} else if (req->map[i].rd_locked) {
			__unlock_cache_line_rd(c, line);
			req->map[i].rd_locked = false;
		} else if (req->map[i].wr_locked) {
			__unlock_cache_line_wr(c, line);
			req->map[i].wr_locked = false;
		} else {
			ENV_BUG();
		}
	}
}

/*
 *
 */
void ocf_req_unlock_entry(struct ocf_cache *cache,
		struct ocf_request *req, uint32_t entry)
{
	struct ocf_cache_line_concurrency *c = req->cache->device->concurrency.cache_line;

	ENV_BUG_ON(req->map[entry].status == LOOKUP_MISS);

	if (req->map[entry].rd_locked && req->map[entry].wr_locked) {
		ENV_BUG();
	} else if (req->map[entry].rd_locked) {
		__unlock_cache_line_rd(c, req->map[entry].coll_idx);
		req->map[entry].rd_locked = false;
	} else if (req->map[entry].wr_locked) {
		__unlock_cache_line_wr(c, req->map[entry].coll_idx);
		req->map[entry].wr_locked = false;
	} else {
		ENV_BUG();
	}
}

/*
 *
 */
bool ocf_cache_line_is_used(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	struct ocf_cache_line_concurrency *c = cache->device->concurrency.cache_line;

	ENV_BUG_ON(line >= cache->device->collision_table_entries);

	if (env_atomic_read(&(c->access[line])))
		return true;

	if (ocf_cache_line_are_waiters(cache, line))
		return true;
	else
		return false;
}

/*
 *
 */
bool ocf_cache_line_are_waiters(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	struct ocf_cache_line_concurrency *c = cache->device->concurrency.cache_line;
	bool are;
	unsigned long flags = 0;

	ENV_BUG_ON(line >= cache->device->collision_table_entries);

	/* Lock waiters list */
	__lock_waiters_list(c, line, flags);

	are = __are_waiters(c, line);

	__unlock_waiters_list(c, line, flags);

	return are;
}

/*
 *
 */
uint32_t ocf_cache_line_concurrency_suspended_no(struct ocf_cache *cache)
{
	struct ocf_cache_line_concurrency *c = cache->device->concurrency.cache_line;

	return env_atomic_read(&c->waiting);
}

bool ocf_cache_line_try_lock_rd(struct ocf_cache *cache, ocf_cache_line_t line)
{
	struct ocf_cache_line_concurrency *c = cache->device->concurrency.cache_line;
	return __lock_cache_line_rd(c, line, NULL, NULL, 0);
}

/*
 *
 */
void ocf_cache_line_unlock_rd(struct ocf_cache *cache, ocf_cache_line_t line)
{
	struct ocf_cache_line_concurrency *c = cache->device->concurrency.cache_line;

	OCF_DEBUG_RQ(cache, "Cache line = %u", line);

	__unlock_cache_line_rd(c, line);
}

