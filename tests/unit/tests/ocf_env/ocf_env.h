/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __LIBOCF_ENV_H__
#define __LIBOCF_ENV_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <linux/limits.h>
#include <linux/stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <semaphore.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/time.h>

#include "ocf_env_list.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef uint64_t sector_t;

#define ENV_PRIu64 "lu"

#define __packed __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))

/* linux sector 512-bytes */
#define ENV_SECTOR_SHIFT	9

#define PAGE_SIZE 4096

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

/* *** MEMORY MANAGEMENT *** */

#define ENV_MEM_NORMAL	0
#define ENV_MEM_NOIO	1
#define ENV_MEM_ATOMIC	2

#define ENV_WARN(cond, fmt, args...) ({})

#define ENV_WARN_ON(cond) ({ \
		if (unlikely(cond)) \
			fprintf(stderr, "WARNING (%s:%d)\n", \
					__FILE__, __LINE__); \
	})

#define ENV_BUG() ({ \
		fprintf(stderr, "BUG (%s:%d)\n", \
				__FILE__, __LINE__); \
		assert(0); \
		abort(); \
	})

#define ENV_BUG_ON(cond) ({ \
		int eval = cond; \
		if (eval) { \
			print_message("%s:%u BUG: %s\n", __FILE__, __LINE__, #cond); \
			bug_on(eval); \
		} \
	})

#define container_of(ptr, type, member) ({                      \
       const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
       (type *)( (char *)__mptr - offsetof(type, member) );})

/* ATOMICS */
#ifndef atomic_read
#define atomic_read(ptr)       (*(__typeof__(*ptr) *volatile) (ptr))
#endif

#ifndef atomic_set
#define atomic_set(ptr, i)     ((*(__typeof__(*ptr) *volatile) (ptr)) = (i))
#endif

#define likely(x) (x)
#define unlikely(x) (x)

/*
 * Bug on for testing
 */
void bug_on(int cond);

void *env_malloc(size_t size, int flags);

void *env_zalloc(size_t size, int flags);

void env_free(const void *ptr);

void *env_vmalloc(size_t size);

void *env_vzalloc(size_t size);

void env_vfree(const void *ptr);

uint64_t env_get_free_memory(void);

/* *** ALLOCATOR *** */

typedef struct _env_allocator env_allocator;

env_allocator *env_allocator_create(uint32_t size, const char *name);

void env_allocator_destroy(env_allocator *allocator);

void *env_allocator_new(env_allocator *allocator);

void env_allocator_del(env_allocator *allocator, void *item);

/* *** MUTEX *** */

typedef struct {
	pthread_mutex_t m;
} env_mutex;

int env_mutex_init(env_mutex *mutex);

int env_mutex_destroy(env_mutex *mutex);

void env_mutex_lock(env_mutex *mutex);

int env_mutex_lock_interruptible(env_mutex *mutex);

void env_mutex_unlock(env_mutex *mutex);

/* *** RECURSIVE MUTEX *** */

typedef env_mutex env_rmutex;

int env_rmutex_init(env_rmutex *rmutex);

void env_rmutex_lock(env_rmutex *rmutex);

int env_rmutex_lock_interruptible(env_rmutex *rmutex);

void env_rmutex_unlock(env_rmutex *rmutex);

/* *** RW SEMAPHORE *** */
typedef struct {
	pthread_rwlock_t lock;
} env_rwsem;

int env_rwsem_init(env_rwsem *s);

void env_rwsem_up_read(env_rwsem *s);

void env_rwsem_down_read(env_rwsem *s);

int env_rwsem_down_read_trylock(env_rwsem *s);

void env_rwsem_up_write(env_rwsem *s);

void env_rwsem_down_write(env_rwsem *s);

int env_rwsem_down_write_trylock(env_rwsem *s);

/* *** ATOMIC VARIABLES *** */

typedef int env_atomic;

typedef long env_atomic64;

int env_atomic_read(const env_atomic *a);

void env_atomic_set(env_atomic *a, int i);

void env_atomic_add(int i, env_atomic *a);

void env_atomic_sub(int i, env_atomic *a);

void env_atomic_inc(env_atomic *a);

void env_atomic_dec(env_atomic *a);

bool env_atomic_dec_and_test(env_atomic *a);

int env_atomic_add_return(int i, env_atomic *a);

int env_atomic_sub_return(int i, env_atomic *a);

int env_atomic_inc_return(env_atomic *a);

int env_atomic_dec_return(env_atomic *a);

int env_atomic_cmpxchg(env_atomic *a, int old, int new_value);

int env_atomic_add_unless(env_atomic *a, int i, int u);

long env_atomic64_read(const env_atomic64 *a);

void env_atomic64_set(env_atomic64 *a, long i);

void env_atomic64_add(long i, env_atomic64 *a);

void env_atomic64_sub(long i, env_atomic64 *a);

void env_atomic64_inc(env_atomic64 *a);

void env_atomic64_dec(env_atomic64 *a);

long env_atomic64_cmpxchg(env_atomic64 *a, long old, long new);

typedef int Coroutine;

/* *** COMPLETION *** */
struct completion {
	bool completed;
	bool waiting;
	Coroutine *co;
};

typedef struct completion env_completion;

void env_completion_init(env_completion *completion);
void env_completion_wait(env_completion *completion);
void env_completion_complete(env_completion *completion);

/* *** SPIN LOCKS *** */

typedef struct {
} env_spinlock;

int env_spinlock_init(env_spinlock *l);

int env_spinlock_destroy(env_spinlock *l);

void env_spinlock_lock(env_spinlock *l);

int env_spinlock_trylock(env_spinlock *l);

void env_spinlock_unlock(env_spinlock *l);

#define env_spinlock_lock_irqsave(l, flags) \
	env_spinlock_lock(l); (void)flags;

#define env_spinlock_unlock_irqrestore(l, flags) \
	env_spinlock_unlock(l); (void)flags;

/* *** RW LOCKS *** */

typedef struct {
} env_rwlock;

void env_rwlock_init(env_rwlock *l);

void env_rwlock_read_lock(env_rwlock *l);

void env_rwlock_read_unlock(env_rwlock *l);

void env_rwlock_write_lock(env_rwlock *l);

void env_rwlock_write_unlock(env_rwlock *l);

/* *** WAITQUEUE *** */

typedef struct {
	bool waiting;
	bool completed;
	Coroutine *co;
} env_waitqueue;

#define env_waitqueue_wait(w, condition)	\
({						\
	int __ret = 0;				\
	if (!(condition) && !w.completed) {	\
		w.waiting = true;		\
	}					\
	w.co = NULL;				\
	w.waiting = false;			\
	w.completed = false;			\
	__ret = __ret;				\
})

/* *** BIT OPERATIONS *** */

void env_bit_set(int nr, volatile void *addr);

void env_bit_clear(int nr, volatile void *addr);

bool env_bit_test(int nr, const volatile unsigned long *addr);

/* *** SCHEDULING *** */

void env_touch_softlockup_wd(void);

int env_in_interrupt(void);

uint64_t env_get_tick_count(void);

uint64_t env_ticks_to_msecs(uint64_t j);

uint64_t env_ticks_to_secs(uint64_t j);

uint64_t env_secs_to_ticks(uint64_t j);

/* *** STRING OPERATIONS *** */

int env_memset(void *dest, size_t count, int ch);

int env_memcpy(void *dest, size_t destsz, const void * src, size_t count);

int env_memcmp(const void *str1, size_t n1, const void *str2, size_t n2,
		int *diff);

int env_strncpy(char * dest, size_t destsz, const char *src, size_t srcsz);

size_t env_strnlen(const char *str, size_t strsz);

int env_strncmp(const char * str1, const char * str2, size_t num);

/* *** SORTING *** */

void env_sort(void *base, size_t num, size_t size,
		int (*cmp_fn)(const void *, const void *),
		void (*swap_fn)(void *, void *, int size));

void env_msleep(uint64_t n);

/* *** CRC *** */

uint32_t env_crc32(uint32_t crc, uint8_t const *data, size_t len);

void env_cond_resched(void);

#endif /* __OCF_ENV_H__ */
