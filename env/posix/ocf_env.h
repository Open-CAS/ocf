/*
 * Copyright(c) 2019-2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_ENV_H__
#define __OCF_ENV_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <linux/limits.h>
#include <linux/stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <semaphore.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <zlib.h>

#include "ocf_env_list.h"
#include "ocf_env_headers.h"
#include "ocf/ocf_err.h"

/* linux sector 512-bytes */
#define ENV_SECTOR_SHIFT	9

/**
 * @def OCF_ALLOCATOR_NAME_MAX
 * @brief max lenght of allocator's name
 */
#define OCF_ALLOCATOR_NAME_MAX 128

/**
 * @def PAGE_SIZE
 * @brief default page size in bits
 */
#define PAGE_SIZE 4096

/**
 * @def DIV_ROUND_UP(n, d)
 * @brief rounds up division result
 */
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

/**
 * @def min(a,b)
 * @brief checks which number is lower
 */
#define min(a,b) MIN(a,b)

/**
 * @def ENV_PRIu64
 * @brief expands to 'long unsigned' abbreviation
 */
#define ENV_PRIu64 "lu"

/** @addtogroup ABBREVIATIONS
 * abbreviations for unsigned integers with fixed size
 * @{
 */

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef uint64_t sector_t;
/** @} */

/**
 * @def __packed
 * @brief extends to __attribute__((packed))
 */
#define __packed	__attribute__((packed))

/**
 * @def likely(cond)
 * @brief checks if condition \a cond value is casted to true
 */
#define likely(cond)       __builtin_expect(!!(cond), 1)

/**
 * @def unlikely(cond)
 * @brief checks if condition \a cond value is casted to false
 */
#define unlikely(cond)     __builtin_expect(!!(cond), 0)

/** @addtogroup MEMORY_MANAGEMENT
 * definitions for ENV_MEM_* macros - number values
 * @{
 */

#define ENV_MEM_NORMAL	0
#define ENV_MEM_NOIO	0
#define ENV_MEM_ATOMIC	0
/** @} */

/** @addtogroup DEBUGGING
 * definitions for debugging macros - warns and asserts
 * @{
 */

/**
 * @def ENV_WARN(cond, fmt...)
 * @brief overwrites kernel macro WARN
 * @details prints formatted message \a fmt to stdout
 */
#define ENV_WARN(cond, fmt...)		printf(fmt)

/**
 * @def ENV_WARN_ON(cond)
 * @brief overwrites kernel macro WARN_ON
 * @details extends to semicolon and does nothing
 */
#define ENV_WARN_ON(cond)		;

/**
 * @def ENV_WARN_ONCE(cond, fmt...)
 * @brief overwrites kernel macro WARN_ONCE
 * @details sends once formatted message \a fmt to stdout
 */
#define ENV_WARN_ONCE(cond, fmt...)	ENV_WARN(cond, fmt)

/**
 * @def ENV_BUG()
 * @brief aborts program execution with error message send to stderr
 */
#define ENV_BUG()			assert(0)

/**
 * @def ENV_BUG_ON(cond)
 * @brief checks if \a cond makes program pointless and program
 * should terminate with error
 */
#define ENV_BUG_ON(cond)		do { if (cond) ENV_BUG(); } while (0)

/**
 * @def ENV_BUILD_BUG_ON(cond)
 * @brief checks during building if \a cond makes program pointless 
 * and interrupt building with error
 */
#define ENV_BUILD_BUG_ON(cond)		_Static_assert(!(cond), "static "\
					"assertion failure")
/** @} */

/** @addtogroup MISC_UTILITIES
 * definitions for miscellaneous utilities
 * @{
 */

/**
 * @def container_of(ptr, type, member)
 * @brief checks members' types of examined container
 */
#define container_of(ptr, type, member) ({          \
	const typeof(((type *)0)->member)*__mptr = (ptr);    \
	(type *)((char *)__mptr - offsetof(type, member)); })

/**
 * @def ARRAY_SIZE(x)
 * @brief returns number of elements in array
 */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
/** @} */

/** @addtogroup STRING_OPERATIONS 
 * definitions for custom string operations based on the <em>Safe C Library</em>
 * @{
 */

/**
 * @def env_memcpy(dest, dmax, src, slen)
 * @brief copies chosen part of memory to another with check
 * if source part doesn't exceeds destination's free space
 * and if so, copy just part of source's memory block
 */
#define env_memcpy(dest, dmax, src, slen) ({ \
		memcpy(dest, src, min(dmax, slen)); \
		0; \
	})

/**
 * @def env_memset(dest, dmax, val)
 * @brief fills chosen memory block with chosen value
 */
#define env_memset(dest, dmax, val) ({ \
		memset(dest, val, dmax); \
		0; \
	})

/**
 * @def env_memcmp(s1, s1max, s2, s2max, diff)
 * @brief compares chosen memory block with other with check
 * if one block isn't bigger than another and if so, compares
 * only equal to smaller block's size part of the bigger one
 */
#define env_memcmp(s1, s1max, s2, s2max, diff) ({ \
		*diff = memcmp(s1, s2, min(s1max, s2max)); \
		0; \
	})

/**
 * @def env_strdup
 * @brief returns pointer to allocated space with terminated 
 * string of at most N bytes
 */
#define env_strdup strndup

/**
 * @def env_strnlen(s, smax)
 * @brief checks if string terminates in \a smax bytes and return its lenght,
 * otherwise returns \a smax
 */
#define env_strnlen(s, smax) strnlen(s, smax)

/**
 * @def env_strncmp(s1, slen1, s2, slen2)
 * @brief compares chosen string with other with check
 * if one string isn't longer than another and if so, compares
 * only equal to shorter string's size part of the longer one
 */
#define env_strncmp(s1, slen1, s2, slen2) strncmp(s1, s2, min(slen1, slen2))

/**
 * @def env_strncpy(dest, dmax, src, slen)
 * @brief copies not more than slen successive characters from the array
 * pointed to by src to the array pointed to by dest. Characters that follow 
 * a null character are not copied. If no null character was copied from src,
 * then dest[n-1] is set to a null character.
 */
#define env_strncpy(dest, dmax, src, slen) ({ \
		strncpy(dest, src, min(dmax - 1, slen)); \
		dest[dmax - 1] = '\0'; \
		0; \
	})
/** @} */

/** @addtogroup MEMORY_MANAGEMENT
 * @{
 */

/**
 * @brief wrapper for malloc
 *
 * @param size bytes of memory to be allocated
 * @param flags memory management flags
 *
 * @retval void *
 */
static inline void *env_malloc(size_t size, int flags)
{
	return malloc(size);
}

/**
 * @brief wrapper for malloc with zeroing allocated space
 *
 * @param size bytes of memory to be allocated and zeroed
 * @param flags memory management flags
 *
 * @retval void *
 */
static inline void *env_zalloc(size_t size, int flags)
{
	void *ptr = malloc(size);

	if (ptr)
		memset(ptr, 0, size);

	return ptr;
}

/**
 * @brief wrapper for free
 *
 * @param ptr pointer to memory to be freed
 */
static inline void env_free(const void *ptr)
{
	free((void *)ptr);
}

/**
 * @brief wrapper for malloc
 *
 * @param size bytes of memory to be allocated
 * @param flags memory management flags
 *
 * @retval void *
 */
static inline void *env_vmalloc_flags(size_t size, int flags)
{
	return malloc(size);
}

/**
 * @brief wrapper for env_zalloc
 *
 * @param size bytes of memory to be allocated and zeroed
 * @param flags memory management flags
 *
 * @retval void *
 */
static inline void *env_vzalloc_flags(size_t size, int flags)
{
	return env_zalloc(size, 0);
}

/**
 * @brief wrapper for malloc
 *
 * @param size bytes of memory to be allocated
 *
 * @retval void *
 */
static inline void *env_vmalloc(size_t size)
{
	return malloc(size);
}

/**
 * @brief wrapper for env_zalloc
 *
 * @param size bytes of memory to be allocated and zeroed
 *
 * @retval void *
 */
static inline void *env_vzalloc(size_t size)
{
	return env_zalloc(size, 0);
}

/**
 * @brief wrapper for free
 *
 * @param ptr pointer to memory to be freed
 */
static inline void env_vfree(const void *ptr)
{
	free((void *)ptr);
}
/** @} */

/** @addtogroup SECURE_MEMORY_MANAGEMENT
 * OCF adapter can opt to take additional steps to securely allocate and free
 * memory used by OCF to store cache metadata. This is to prevent other
 * entities in the system from acquiring parts of OCF cache metadata via
 * memory allocations. If this is not a concern in given product, secure
 * alloc/free should default to vmalloc/vfree.
 *
 * Memory returned from secure alloc is not expected to be physically continous
 * nor zeroed.
 * @{
 */

/**
 * @def SECURE_MEMORY_HANDLING
 * @brief default to standard memory allocations for secure allocations
 * @details decides if \a env_secure_* functions would run in secure mode
 * if defined to any value that converts to false, then 'secure' mode is off
 */
#define SECURE_MEMORY_HANDLING 0

/**
 * @brief wrapper for malloc with option to reserve memory exclusively
 *
 * @param size bytes of memory to be allocated
 *
 * @retval void *
 */
static inline void *env_secure_alloc(size_t size)
{
	void *ptr = malloc(size);

#if SECURE_MEMORY_HANDLING
	if (ptr && mlock(ptr, size)) {
		free(ptr);
		ptr = NULL;
	}
#endif

	return ptr;
}

/**
 * @brief wrapper for free with option to zero freed space and unlock 
 * previously reserved space
 *
 * @param ptr pointer to memory to be freed
 */
static inline void env_secure_free(const void *ptr, size_t size)
{
	if (ptr) {
#if SECURE_MEMORY_HANDLING
		memset(ptr, 0, size);
		/* TODO: flush CPU caches ? */
		ENV_BUG_ON(munlock(ptr));
#endif
		free((void*)ptr);
	}
}

/**
 * @brief cast (-1) to unsigned 64-bits integer - get its max value
 *
 * @retval 18446744073709551615 / 0xffffffffffffffff
 */
static inline uint64_t env_get_free_memory(void)
{
	return (uint64_t)(-1);
}
/** @} */

/** @addtogroup ALLOCATOR
 * @{
 */

/**
 * @struct env_allocator ocf_env.h "env/posix/ocf_env.h"
 * @brief _env_allocator struct wrapper
 * @details contains:
 * <tt>char *name</tt> - memory pool ID unique name 
 * <tt>uint32_t item_size</tt> - size of specific item of memory pool
 * <tt>env_atomic count</tt> - number of currently allocated items in pool
 */
typedef struct _env_allocator env_allocator;

/**
 * @brief creates new env_allocator struct
 * @details tries to allocate zeroed memory, adds size of specific item
 * and formats name; if not succeeded call destroy on initialized allocator
 *
 * @param size bytes of memory to be allocated
 * @param fmt_name pointer to space with unique name
 * @param ... amount of currently allocated items in pool
 *
 * @retval pointer ot env_allocator if creation succeed
 * @retval NULL if not enough memory for new allocator, 
 * name is empty or too long
 */
env_allocator *env_allocator_create(uint32_t size, const char *fmt_name, ...);

/**
 * @brief destroys env_allocator struct and frees memory blocks 
 * reserved by deleted allocator and its name
 *
 * @param allocator pointer to env_allocator struct to be destroyed
 * 
 * @warning cleanup problem
 */
void env_allocator_destroy(env_allocator *allocator);

/**
 * @brief creates new allocator's item and increments atomic counter
 * 
 * @param allocator pointer to allocator to which item should be added
 * 
 * @retval address to space where amount of currently allocated items is stored
 */
void *env_allocator_new(env_allocator *allocator);

/**
 * @brief deletes new allocator's item, decrements atomic counter
 * and frees memory block reserved by deleted item
 * 
 * @param allocator pointer to allocator from which item should be removed
 * @param item pointer to item which should be removed
 */
void env_allocator_del(env_allocator *allocator, void *item);
/** @} */

/** @addtogroup MUTEX
 * @{
 */

/**
 * @struct env_mutex ocf_env.h "env/posix/ocf_env.h"
 * @brief single mutex struct
 * @details contains:
 * <tt>pthread_mutex_t m</tt> - mutex union
 */
typedef struct {
	pthread_mutex_t m;
} env_mutex;

/**
 * @def env_cond_resched() 
 * @brief conditional rescheduler
 */
#define env_cond_resched()      ({})

/**
 * @brief initiates mutex inside env_mutex struct
 * 
 * @param mutex pointer to env_mutex which should be initiated
 * 
 * @retval 0 if succeed
 * @retval 1 if failed
 */
static inline int env_mutex_init(env_mutex *mutex)
{
	if(pthread_mutex_init(&mutex->m, NULL))
		return 1;

	return 0;
}

/**
 * @brief locks mutex inside env_mutex struct
 * 
 * @param mutex pointer to env_mutex which should be locked
 * 
 * @bug assert if lock failed
 */
static inline void env_mutex_lock(env_mutex *mutex)
{
	ENV_BUG_ON(pthread_mutex_lock(&mutex->m));
}


/**
 * @brief tries to lock mutex inside env_mutex struct
 * 
 * @param mutex pointer to env_mutex which should be locked
 * 
 * @retval 0 if succeed
 * @exception throws exception if lock failed
 */
static inline int env_mutex_trylock(env_mutex *mutex)
{
	return pthread_mutex_trylock(&mutex->m);
}

/**
 * @brief locks mutex inside env_mutex struct, operation can be interrupted
 * 
 * @param mutex pointer to env_mutex which should be locked
 * 
 * @retval 0
 */
static inline int env_mutex_lock_interruptible(env_mutex *mutex)
{
	env_mutex_lock(mutex);
	return 0;
}

/**
 * @brief unlock mutex inside env_mutex struct
 * 
 * @param mutex pointer to env_mutex which should be unlocked
 * 
 * @bug assert if unlock failed
 */
static inline void env_mutex_unlock(env_mutex *mutex)
{
	ENV_BUG_ON(pthread_mutex_unlock(&mutex->m));
}

/**
 * @brief destroys mutex inside env_mutex struct
 * 
 * @param mutex pointer to env_mutex which should be deleted
 * 
 * @retval 0 if succeed
 * @retval 1 if failed
 */
static inline int env_mutex_destroy(env_mutex *mutex)
{
	if(pthread_mutex_destroy(&mutex->m))
		return 1;

	return 0;
}
/** @} */

/** @addtogroup RECURSIVE_MUTEX
 * @{
 */

/**
 * @struct env_mutex ocf_env.h "env/posix/ocf_env.h"
 * @brief env_mutex struct wrapper
 * @details contains:
 * <tt>pthread_mutex_t m</tt> - mutex union
 */
typedef env_mutex env_rmutex;

/**
 * @brief initiates mutex inside env_rmutex struct as recursive
 * 
 * @param rmutex pointer to env_rmutex which should be initiated
 * 
 * @retval 0
 */
static inline int env_rmutex_init(env_rmutex *rmutex)
{
	pthread_mutexattr_t attr;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&rmutex->m, &attr);

	return 0;
}

/**
 * @brief locks mutex inside env_rmutex struct
 * 
 * @param rmutex pointer to env_rmutex which should be locked
 * 
 * @bug assert if lock failed
 */
static inline void env_rmutex_lock(env_rmutex *rmutex)
{
	env_mutex_lock(rmutex);
}

/**
 * @brief locks mutex inside env_rmutex struct, operation can be interrupted
 * 
 * @param rmutex pointer to env_rmutex which should be locked
 * 
 * @retval 0 if succeed
 * @exception throws exception if lock failed
 */
static inline int env_rmutex_lock_interruptible(env_rmutex *rmutex)
{
	return env_mutex_lock_interruptible(rmutex);
}

/**
 * @brief unlocks mutex inside env_rmutex struct
 * 
 * @param rmutex pointer to env_rmutex which should be unlocked
 * 
 * @bug assert if unlock failed
 */
static inline void env_rmutex_unlock(env_rmutex *rmutex)
{
	env_mutex_unlock(rmutex);
}

/**
 * @brief destroys mutex inside env_rmutex struct
 * 
 * @param rmutex pointer to env_rmutex which should be deleted
 * 
 * @retval 0 if succeed
 * @retval 1 if failed
 */
static inline int env_rmutex_destroy(env_rmutex *rmutex)
{
	if(pthread_mutex_destroy(&rmutex->m))
		return 1;

	return 0;
}
/** @} */

/** @addtogroup RW_SEMAPHORE
 * @{
 */

/**
 * @struct env_rwsem ocf_env.h "env/posix/ocf_env.h"
 * @brief single read-write lock struct
 * @details contains:
 * <tt>pthread_rwlock_t lock</tt> - read-write lock union
 */
typedef struct {
	 pthread_rwlock_t lock;
} env_rwsem;

/**
 * @brief initiates semaphore inside env_rwsem struct
 * 
 * @param s pointer to env_rwsem which should be initiated
 * 
 * @retval 0 if succeed
 * @exception throws exception if initialization failed
 */
static inline int env_rwsem_init(env_rwsem *s)
{
	return pthread_rwlock_init(&s->lock, NULL);
}

/**
 * @brief unlocks semaphore inside env_rwsem struct
 * 
 * @param s pointer to env_rwsem which should be unlocked
 * 
 * @exception throws exception if unlock failed
 */
static inline void env_rwsem_up_read(env_rwsem *s)
{
	pthread_rwlock_unlock(&s->lock);
}

/**
 * @brief acquire read lock for semaphore inside env_rwsem struct
 * 
 * @param s pointer to env_rwsem which should be read-locked
 * 
 * @bug assert if read lock failed
 */
static inline void env_rwsem_down_read(env_rwsem *s)
{
	ENV_BUG_ON(pthread_rwlock_rdlock(&s->lock));
}

/**
 * @brief tries to acquire read lock for semaphore inside env_rwsem struct
 * 
 * @param s pointer to env_rwsem which should be read-locked
 * 
 * @retval 0 if succeed
 * @exception throws exception if read lock failed
 */
static inline int env_rwsem_down_read_trylock(env_rwsem *s)
{
	return pthread_rwlock_tryrdlock(&s->lock) ? -OCF_ERR_NO_LOCK : 0;
}

/**
 * @brief unlock write lock from semaphore inside env_rwsem struct
 * 
 * @param s pointer to env_rwsem which should be unlocked
 * 
 * @bug assert if write unlock failed
 */
static inline void env_rwsem_up_write(env_rwsem *s)
{
	ENV_BUG_ON(pthread_rwlock_unlock(&s->lock));
}

/**
 * @brief acquire write lock for semaphore inside env_rwsem struct
 * 
 * @param s pointer to env_rwsem which should be write-locked
 * 
 * @bug assert if write lock failed
 */
static inline void env_rwsem_down_write(env_rwsem *s)
{
	ENV_BUG_ON(pthread_rwlock_wrlock(&s->lock));
}

/**
 * @brief tries to acquire write lock for semaphore inside env_rwsem struct
 * 
 * @param s pointer to env_rwsem which should be write-locked
 * 
 * @retval 0 if succeed
 * @exception throws exception if write lock failed
 */
static inline int env_rwsem_down_write_trylock(env_rwsem *s)
{
	return pthread_rwlock_trywrlock(&s->lock) ? -OCF_ERR_NO_LOCK : 0;
}

/**
 * @brief destroys semaphore inside env_rwsem struct
 * 
 * @param s pointer to env_rwsem which should be deleted
 * 
 * @retval 0 if succeed
 * @exception throws exception if destroy failed
 */
static inline int env_rwsem_destroy(env_rwsem *s)
{
	return pthread_rwlock_destroy(&s->lock);
}
/** @} */

/** @addtogroup COMPLETION
 * @{
 */

/**
 * @struct completion ocf_env.h "env/posix/ocf_env.h"
 * @brief single semaphore struct
 * @details contains:
 * <tt>sem_t sem</tt> - semaphore union
 */
struct completion {
	sem_t sem;
};

/**
 * @struct env_completion ocf_env.h "env/posix/ocf_env.h"
 * @brief completion struct wrapper
 * @details contains:
 * <tt>sem_t sem</tt> - semaphore union
 */
typedef struct completion env_completion;

/**
 * @brief initiates non-shared semaphore inside env_completion struct
 * 
 * @param completion pointer to env_completion which should be initiated
 * 
 * @exception throws exception if initialization failed
 */
static inline void env_completion_init(env_completion *completion)
{
	sem_init(&completion->sem, 0, 0);
}

/**
 * @brief waits for semaphore inside env_completion struct to finish work
 * 
 * @param completion pointer to env_completion which should be finished
 */
static inline void env_completion_wait(env_completion *completion)
{
	sem_wait(&completion->sem);
}

/**
 * @brief finishes work of semaphore inside env_completion struct
 * 
 * @param completion pointer to env_completion which should be completed
 * 
 * @exception throws exception if completion failed
 */
static inline void env_completion_complete(env_completion *completion)
{
	sem_post(&completion->sem);
}

/**
 * @brief destroys semaphore inside env_completion struct
 * 
 * @param completion pointer to env_completion which should be deleted
 * 
 * @exception throws exception if destroy failed
 */
static inline void env_completion_destroy(env_completion *completion)
{
	sem_destroy(&completion->sem);
}
/** @} */

/** @addtogroup ATOMIC_VARIABLES
 * @{
 */

/**
 * @struct env_atomic ocf_env.h "env/posix/ocf_env.h"
 * @brief single volatile 32-bit counter struct
 * @details contains:
 * <tt>volatile int counter</tt> - 32-bit counter
 */
typedef struct {
	volatile int counter;
} env_atomic;

/**
 * @struct env_atomic64 ocf_env.h "env/posix/ocf_env.h"
 * @brief single volatile 64-bit counter struct
 * @details contains:
 * <tt>volatile long counter</tt> - 64-bit counter
 */
typedef struct {
	volatile long counter;
} env_atomic64;

/**
 * @brief returns current counter value
 * 
 * @param a pointer to env_atomic which counter should be read
 * 
 * @retval current counter value
 */
static inline int env_atomic_read(const env_atomic *a)
{
	return a->counter; /* TODO */
}

/**
 * @brief sets counter value to \a i
 * 
 * @param a pointer to env_atomic which counter should be set
 * @param i value to which counter value would be set
 */
static inline void env_atomic_set(env_atomic *a, int i)
{
	a->counter = i; /* TODO */
}

/**
 * @brief adds \a i to counter value
 * 
 * @param i value which would be added to counter value
 * @param a pointer to env_atomic which counter should be increased
 */
static inline void env_atomic_add(int i, env_atomic *a)
{
	__sync_add_and_fetch(&a->counter, i);
}

/**
 * @brief subtracts \a i from counter value
 * 
 * @param i value which would be deducted from counter value
 * @param a pointer to env_atomic which counter should be decreased
 */
static inline void env_atomic_sub(int i, env_atomic *a)
{
	__sync_sub_and_fetch(&a->counter, i);
}

/**
 * @brief increase counter value by 1
 * 
 * @param a pointer to env_atomic which counter should be increased
 */
static inline void env_atomic_inc(env_atomic *a)
{
	env_atomic_add(1, a);
}

/**
 * @brief decrease counter value by 1
 * 
 * @param a pointer to env_atomic which counter should be decreased
 */
static inline void env_atomic_dec(env_atomic *a)
{
	env_atomic_sub(1, a);
}

/**
 * @brief decrease counter value by 1 and check if operation succeded
 * 
 * @param a pointer to env_atomic which counter should be decreased
 * 
 * @retval true if operation succeded
 * @retval false if operation failed
 */
static inline bool env_atomic_dec_and_test(env_atomic *a)
{
	return __sync_sub_and_fetch(&a->counter, 1) == 0;
}

/**
 * @brief adds \a i to counter value
 * 
 * @param i value which would be added to counter value
 * @param a pointer to env_atomic which counter should be increased
 * 
 * @retval counter value after operation
 */
static inline int env_atomic_add_return(int i, env_atomic *a)
{
	return __sync_add_and_fetch(&a->counter, i);
}

/**
 * @brief subtracts \a i from counter value and return result
 * 
 * @param i value which would be deducted from counter value
 * @param a pointer to env_atomic which counter should be decreased
 * 
 * @retval counter value after operation
 */
static inline int env_atomic_sub_return(int i, env_atomic *a)
{
	return __sync_sub_and_fetch(&a->counter, i);
}

/**
 * @brief increase counter value by 1 and return it
 * 
 * @param a pointer to env_atomic which counter should be increased
 * 
 * @retval counter value after operation
 */
static inline int env_atomic_inc_return(env_atomic *a)
{
	return env_atomic_add_return(1, a);
}

/**
 * @brief decrease counter value by 1 and return it
 * 
 * @param a pointer to env_atomic which counter should be decreased
 * 
 * @retval counter value after operation
 */
static inline int env_atomic_dec_return(env_atomic *a)
{
	return env_atomic_sub_return(1, a);
}

/**
 * @brief check if counter value equals \a old and if yes, set it to \a new_value
 * 
 * @param a pointer to env_atomic which counter should be modified
 * @param old value with which counter value would be compared 
 * @param new_value vale to which counter value would be set
 * if counter value equals \a old
 * 
 * @retval counter value after operation
 */
static inline int env_atomic_cmpxchg(env_atomic *a, int old, int new_value)
{
	return __sync_val_compare_and_swap(&a->counter, old, new_value);
}

/**
 * @brief adds \a i to counter value until counter reaches \a u
 * 
 * @param a pointer to env_atomic which counter should be increased
 * @param i value which would be added to counter value
 * @param u target counter's value
 * 
 * @retval true if previous counter changed value
 * @retval false otherwise
 */
static inline int env_atomic_add_unless(env_atomic *a, int i, int u)
{
	int c, old;
	c = env_atomic_read(a);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = env_atomic_cmpxchg((a), c, c + (i));
		if (likely(old == c))
			break;
		c = old;
	}
	return c != (u);
}

/**
 * @brief returns current counter value
 * 
 * @param a pointer to env_atomic64 which counter should be read
 * 
 * @retval current counter value
 */
static inline long env_atomic64_read(const env_atomic64 *a)
{
	return a->counter; /* TODO */
}

/**
 * @brief sets counter value to \a i
 * 
 * @param a pointer to env_atomic64 which counter should be set
 * @param i value to which counter value would be set
 */
static inline void env_atomic64_set(env_atomic64 *a, long i)
{
	a->counter = i; /* TODO */
}

/**
 * @brief adds \a i to counter value
 * 
 * @param i value which would be added to counter value
 * @param a pointer to env_atomic64 which counter should be increased
 */
static inline void env_atomic64_add(long i, env_atomic64 *a)
{
	__sync_add_and_fetch(&a->counter, i);
}

/**
 * @brief subtracts \a i from counter value
 * 
 * @param i value which would be deducted from counter value
 * @param a pointer to env_atomic64 which counter should be decreased
 */
static inline void env_atomic64_sub(long i, env_atomic64 *a)
{
	__sync_sub_and_fetch(&a->counter, i);
}

/**
 * @brief increase counter value by 1
 * 
 * @param a pointer to env_atomic64 which counter should be increased
 */
static inline void env_atomic64_inc(env_atomic64 *a)
{
	env_atomic64_add(1, a);
}

/**
 * @brief decrease counter value by 1
 * 
 * @param a pointer to env_atomic64 which counter should be decreased
 */
static inline void env_atomic64_dec(env_atomic64 *a)
{
	env_atomic64_sub(1, a);
}

/**
 * @brief increase counter value by 1 and return it
 * 
 * @param a pointer to env_atomic64 which counter should be increased
 * 
 * @retval counter value after operation
 */
static inline long env_atomic64_inc_return(env_atomic64 *a)
{
	return __sync_add_and_fetch(&a->counter, 1);
}

/**
 * @brief check if counter value equals \a old and if yes, set it to \a new_value
 * 
 * @param a pointer to env_atomic64 which counter should be modified
 * @param old_v value with which counter value would be compared 
 * @param new_v vale to which counter value would be set
 * if counter value equals \a old
 * 
 * @retval counter value after operation
 */
static inline long env_atomic64_cmpxchg(env_atomic64 *a, long old_v, long new_v)
{
	return __sync_val_compare_and_swap(&a->counter, old_v, new_v);
}
/** @} */

/** @addtogroup SPIN_LOCKS
 * @{
 */

/**
 * @struct env_spinlock ocf_env.h "env/posix/ocf_env.h"
 * @brief single POSIX spinlock struct
 * @details contains:
 * <tt>pthread_spinlock_t lock</tt> - 32-bit volatile number
 */
typedef struct {
	pthread_spinlock_t lock;
} env_spinlock;

/**
 * @brief initiates non-shared spinlock inside env_spinlock struct
 * 
 * @param l pointer to env_spinlock which should be initiated
 * 
 * @retval 0 if succeed
 * @exception throws exception if lock init failed
 */
static inline int env_spinlock_init(env_spinlock *l)
{
	return pthread_spin_init(&l->lock, 0);
}

/**
 * @brief tries to lock spinlock inside env_spinlock struct
 * 
 * @param l pointer to env_spinlock which should be locked
 * 
 * @retval 0 if lock succeed
 * @retval 1000005 if lock failed
 * @exception throws exception if lock failed
 */
static inline int env_spinlock_trylock(env_spinlock *l)
{
	return pthread_spin_trylock(&l->lock) ? -OCF_ERR_NO_LOCK : 0;
}

/**
 * @brief waits until spinlock's inside env_spinlock struct is retrieved
 * 
 * @param l pointer to env_spinlock which spinlock should be retrieved
 * 
 * @bug assert if spinlock's retrieve failed
 */
static inline void env_spinlock_lock(env_spinlock *l)
{
	ENV_BUG_ON(pthread_spin_lock(&l->lock));
}

/**
 * @brief releases spinlock inside env_spinlock struct
 * 
 * @param l pointer to env_spinlock which should be released
 * 
 * @bug assert if spinlock's release failed
 */
static inline void env_spinlock_unlock(env_spinlock *l)
{
	ENV_BUG_ON(pthread_spin_unlock(&l->lock));
}

/**
 * @def env_spinlock_lock_irqsave(l, flags)
 * @brief waits until spinlock's inside env_spinlock struct is retrieved
 * and disables interrupts with saving previous interrupt state
 */
#define env_spinlock_lock_irqsave(l, flags) \
		(void)flags; \
		env_spinlock_lock(l)

/**
 * @def env_spinlock_unlock_irqrestore(l, flags)
 * @brief releases spinlock inside env_spinlock struct
 * and restores interrupts with loading previous interrupt state
 */
#define env_spinlock_unlock_irqrestore(l, flags) \
		(void)flags; \
		env_spinlock_unlock(l)

/**
 * @brief destroys spinlock inside env_spinlock struct
 * 
 * @param l pointer to env_spinlock which should be deleted
 * 
 * @bug assert if spinlock's destroy failed
 */
static inline void env_spinlock_destroy(env_spinlock *l)
{
	ENV_BUG_ON(pthread_spin_destroy(&l->lock));
}
/** @} */

/** @addtogroup RW_LOCKS
 * @{
 */

/**
 * @struct env_rwlock ocf_env.h "env/posix/ocf_env.h"
 * @brief single read-write lock struct
 * @details contains:
 * <tt>pthread_rwlock_t lock</tt> - read-write lock union
 */
typedef struct {
	pthread_rwlock_t lock;
} env_rwlock;

/**
 * @brief initiates read-write lock inside env_rwlock struct
 * 
 * @param l pointer to env_rwlock which should be initiated
 * 
 * @bug assert if initialization failed
 */
static inline void env_rwlock_init(env_rwlock *l)
{
	ENV_BUG_ON(pthread_rwlock_init(&l->lock, NULL));
}

/**
 * @brief acquire read lock for read-write lock inside env_rwlock struct
 * 
 * @param l pointer to env_rwlock which should be read-locked
 * 
 * @bug assert if read lock failed
 */
static inline void env_rwlock_read_lock(env_rwlock *l)
{
	ENV_BUG_ON(pthread_rwlock_rdlock(&l->lock));
}

/**
 * @brief unlocks read-write lock inside env_rwlock struct
 * 
 * @param l pointer to env_rwlock which should be unlocked
 * 
 * @bug assert if read unlock failed
 */
static inline void env_rwlock_read_unlock(env_rwlock *l)
{
	ENV_BUG_ON(pthread_rwlock_unlock(&l->lock));
}

/**
 * @brief acquire write lock for read-write lock inside env_rwlock struct
 * 
 * @param l pointer to env_rwlock which should be write-locked
 * 
 * @bug assert if write lock failed
 */
static inline void env_rwlock_write_lock(env_rwlock *l)
{
	ENV_BUG_ON(pthread_rwlock_wrlock(&l->lock));
}

/**
 * @brief unlocks read-write lock inside env_rwlock struct
 * 
 * @param l pointer to env_rwlock which should be unlocked
 * 
 * @bug assert if write unlock failed
 */
static inline void env_rwlock_write_unlock(env_rwlock *l)
{
	ENV_BUG_ON(pthread_rwlock_unlock(&l->lock));
}

/**
 * @brief destroys read-write lock inside env_rwlock struct
 * 
 * @param l pointer to env_rwlock which should be deleted
 * 
 * @bug assert if destroy failed
 */
static inline void env_rwlock_destroy(env_rwlock *l)
{
	ENV_BUG_ON(pthread_rwlock_destroy(&l->lock));
}
/** @} */

/** @addtogroup BIT_OPERATIONS
 * Functions using built-ins for atomic memory access
 * @{
 */

/**
 * @brief sets bit value to 1
 * 
 * @param nr 32-bit number
 * @param addr pointer to volatile address
 */
static inline void env_bit_set(int nr, volatile void *addr)
{
	char *byte = (char *)addr + (nr >> 3);
	char mask = 1 << (nr & 7);

	__sync_or_and_fetch(byte, mask);
}

/**
 * @brief clears bit value - sets it to zero
 * 
 * @param nr 32-bit number
 * @param addr pointer to volatile address
 */
static inline void env_bit_clear(int nr, volatile void *addr)
{
	char *byte = (char *)addr + (nr >> 3);
	char mask = 1 << (nr & 7);

	mask = ~mask;
	__sync_and_and_fetch(byte, mask);
}

/**
 * @brief checks bit value
 * 
 * @param nr 32-bit number
 * @param addr pointer to volatile address
 */
static inline bool env_bit_test(int nr, const volatile unsigned long *addr)
{
	const char *byte = (char *)addr + (nr >> 3);
	char mask = 1 << (nr & 7);

	return !!(*byte & mask);
}
/** @} */

/** @addtogroup SCHEDULING
 * @{
 */

/**
 * @brief returns 0
 * 
 * @retval 0
 */
static inline int env_in_interrupt(void)
{
	return 0;
}

/**
 * @brief checks current time of day
 * 
 * @retval current time of day converted to microseconds
 */
static inline uint64_t env_get_tick_count(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}

/**
 * @brief converts microseconds to nanoseconds
 * 
 * @param j unsigned long number
 * 
 * @retval j * 1 000
 */
static inline uint64_t env_ticks_to_nsecs(uint64_t j)
{
	return j * 1000;
}

/**
 * @brief converts microseconds to miliseconds
 * 
 * @param j unsigned long number
 * 
 * @retval j / 1 000
 */
static inline uint64_t env_ticks_to_msecs(uint64_t j)
{
	return j / 1000;
}

/**
 * @brief converts microseconds to seconds
 * 
 * @param j unsigned long number
 * 
 * @retval j / 1 000 000
 */
static inline uint64_t env_ticks_to_secs(uint64_t j)
{
	return j / 1000000;
}

/**
 * @brief converts seconds to microseconds
 * 
 * @param j unsigned long number
 * 
 * @retval j * 1 000 000
 */
static inline uint64_t env_secs_to_ticks(uint64_t j)
{
	return j * 1000000;
}
/** @} */

/** @addtogroup SORTING
 * @{
 */

/**
 * @brief sorts structure with quicksort algorithm
 * 
 * @param base structure to be sorted
 * @param num amount of elements of \a base to be sorted
 * @param size size of single \a base's element in bytes
 * @param cmp_fn pointer to comparing function receiving two constant void pointers
 * and returning int
 * @param swap_fn pointer to swaping function receiving two void pointers and int
 */
static inline void env_sort(void *base, size_t num, size_t size,
		int (*cmp_fn)(const void *, const void *),
		void (*swap_fn)(void *, void *, int size))
{
	qsort(base, num, size, cmp_fn);
}
/** @} */

/** @addtogroup TIME
 * @{
 */

/**
 * @brief sleeps given amount of seconds
 * 
 * @param n amount of seconds to sleep
 */
static inline void env_msleep(uint64_t n)
{
	usleep(n * 1000);
}

/**
 * @struct env_timeval ocf_env.h "env/posix/ocf_env.h"
 * @brief equivalent of timeval struct from \a <time.h> library
 * @details contains:
 * <tt>uint64_t sec</tt> - seconds stored as fixed to 64-bits unsigned integer
 * <tt>uint64_t usec</tt> - microseconds stored as fixed to 64-bits unsigned integer
 */
struct env_timeval {
	uint64_t sec, usec;
};
/** @} */

/** @addtogroup CRC
 * @{
 */
/**
 * @brief Updates a running CRC-32
 * wrapper for crc32 function from \a <zlib.h> library
 * 
 * @param crc cyclic redundancy code
 * @param data pointer to data that would be checked
 * @param len amount of \a data's elements that would be checked
 * 
 * @retval updated CRC-32
 */
uint32_t env_crc32(uint32_t crc, uint8_t const *data, size_t len);
/** @} */

/** @addtogroup EXECUTION_CONTEXTS
 * @{
 */

/** 
 * @brief check execution context
 * @details get_execuction_context must assure that after the call finishes,
 * the caller will not get preempted from current execution context. For userspace
 * \b env we simulate this behavior by acquiring per execution context mutex.
 * As a result the caller might actually get preempted, but no other thread will
 * execute in this context by the time the caller puts current execution ctx.
 * 
 * @retval index of currently used CPU
 * @bug assert if mutex's lock failed
 */
unsigned env_get_execution_context(void);

/** 
 * @brief put down execution context
 * unlocks mutex from given context
 * 
 * @param ctx context which should be unlocked
 */
void env_put_execution_context(unsigned ctx);

/** 
 * @brief checks number of available contexts
 * 
 * @retval number of currently available contexts
 */
unsigned env_get_execution_context_count(void);
/** @} */

#endif /* __OCF_ENV_H__ */
