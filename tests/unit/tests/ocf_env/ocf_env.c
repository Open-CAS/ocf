/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_env.h"
#include <sys/types.h>

#include <setjmp.h>
#include <cmocka.h>

/* BUG ON */
void bug_on(int cond)
{
	/*   Wrap this to use your implementation */
	assert_false(cond);
}

/* MEMORY MANAGEMENT */
void *env_malloc(size_t size, int flags)
{
	return malloc(size);
}

void *env_zalloc(size_t size, int flags)
{
	return calloc(1, size);
}

void env_free(const void *ptr)
{
	return free((void *) ptr);
}

void *env_vmalloc(size_t size)
{
	return malloc(size);
}

void *env_vzalloc(size_t size)
{
	return calloc(1, size);
}

void env_vfree(const void *ptr)
{
	return free((void *) ptr);
}

uint64_t env_get_free_memory(void)
{
	return sysconf(_SC_PAGESIZE) * sysconf(_SC_AVPHYS_PAGES);
}

/* ALLOCATOR */
struct _env_allocator {
	/*!< Memory pool ID unique name */
	char *name;

	/*!< Size of specific item of memory pool */
	uint32_t item_size;

	/*!< Number of currently allocated items in pool */
	env_atomic count;
};

size_t env_allocator_align(size_t size)
{
	if (size <= 2)
		return size;
	return (1ULL << 32) >> __builtin_clz(size - 1);
}

struct _env_allocator_item {
	uint32_t flags;
	uint32_t cpu;
	char data[];
};

void *env_allocator_new(env_allocator *allocator)
{
	struct _env_allocator_item *item = NULL;

	item = calloc(1, allocator->item_size);
	if (item) {
		item->cpu = 0;
		env_atomic_inc(&allocator->count);
	}

	return &item->data;
}

env_allocator *env_allocator_create(uint32_t size, const char *name)
{
	env_allocator *allocator = calloc(1, sizeof(*allocator));

	allocator->item_size = size + sizeof(struct _env_allocator_item);

	allocator->name = strdup(name);

	return allocator;
}

void env_allocator_del(env_allocator *allocator, void *obj)
{
	struct _env_allocator_item *item;

	item = container_of(obj, struct _env_allocator_item, data);

	env_atomic_dec(&allocator->count);

	free(item);
}

void env_allocator_destroy(env_allocator *allocator)
{
	if (allocator) {
		if (env_atomic_read(&allocator->count)) {
			fprintf(stderr, "Not all object deallocated\n");
			ENV_WARN(true, "Cleanup problem\n");
		}

		free(allocator->name);
		free(allocator);
	}
}

/* COMPLETION */
void env_completion_init(env_completion *completion)
{
	function_called();
	check_expected_ptr(completion);
}

void env_completion_wait(env_completion *completion)
{
	function_called();
	check_expected_ptr(completion);
}

void env_completion_complete(env_completion *completion)
{
	function_called();
	check_expected_ptr(completion);
}

/* MUTEX */
int env_mutex_init(env_mutex *mutex)
{
	function_called();
	check_expected_ptr(mutex);
	return mock();
}

void env_mutex_lock(env_mutex *mutex)
{
	function_called();
	check_expected_ptr(mutex);
}

int env_mutex_lock_interruptible(env_mutex *mutex)
{
	function_called();
	check_expected_ptr(mutex);
	return mock();
}

void env_mutex_unlock(env_mutex *mutex)
{
	function_called();
	check_expected_ptr(mutex);
}

/* RECURSIVE MUTEX */
int env_rmutex_init(env_rmutex *rmutex)
{
	function_called();
	check_expected_ptr(rmutex);
	return mock();
}

void env_rmutex_lock(env_rmutex *rmutex)
{
	function_called();
	check_expected_ptr(rmutex);
}

int env_rmutex_lock_interruptible(env_rmutex *rmutex)
{
	function_called();
	check_expected_ptr(rmutex);
	return mock();
}

void env_rmutex_unlock(env_rmutex *rmutex)
{
	function_called();
	check_expected_ptr(rmutex);
}

/* RW SEMAPHORE */
int env_rwsem_init(env_rwsem *s)
{
	function_called();
	check_expected_ptr(s);
	return mock();
}

void env_rwsem_up_read(env_rwsem *s)
{
	function_called();
	check_expected_ptr(s);
}

void env_rwsem_down_read(env_rwsem *s)
{
	function_called();
	check_expected_ptr(s);
}

int env_rwsem_down_read_trylock(env_rwsem *s)
{
	function_called();
	check_expected_ptr(s);
	return mock();
}

void env_rwsem_up_write(env_rwsem *s)
{
	function_called();
	check_expected_ptr(s);
}

void env_rwsem_down_write(env_rwsem *s)
{
	function_called();
	check_expected_ptr(s);
}

int env_rwsem_down_write_trylock(env_rwsem *s)
{
	function_called();
	check_expected_ptr(s);
	return mock();
}

/* ATOMIC VARIABLES */
int env_atomic_read(const env_atomic *a)
{
	return *a;
}

void env_atomic_set(env_atomic *a, int i)
{
	*a = i;
}

void env_atomic_add(int i, env_atomic *a)
{
	*a += i;
}

void env_atomic_sub(int i, env_atomic *a)
{
	*a -= i;
}

void env_atomic_inc(env_atomic *a)
{
	++*a;
}

void env_atomic_dec(env_atomic *a)
{
	--*a;
}

bool env_atomic_dec_and_test(env_atomic *a)
{
	return --*a == 0;
}

int env_atomic_add_return(int i, env_atomic *a)
{
	return *a+=i;
}

int env_atomic_sub_return(int i, env_atomic *a)
{
	return *a-=i;
}

int env_atomic_inc_return(env_atomic *a)
{
	return ++*a;
}

int env_atomic_dec_return(env_atomic *a)
{
	return --*a;
}

int env_atomic_cmpxchg(env_atomic *a, int old, int new_value)
{
	int oldval = *a;
	if (oldval == old)
		*a = new_value;
	return oldval;
}

int env_atomic_add_unless(env_atomic *a, int i, int u)
{
	int c, old;
	c = *a;
	for (;;) {
		if (c == (u))
			break;
		old = env_atomic_cmpxchg((a), c, c + (i));
		if (old == c)
			break;
		c = old;
	}
	return c != (u);
}

long env_atomic64_read(const env_atomic64 *a)
{
	return *a;
}

void env_atomic64_set(env_atomic64 *a, long i)
{
	*a=i;
}

void env_atomic64_add(long i, env_atomic64 *a)
{
	*a += i;
}

void env_atomic64_sub(long i, env_atomic64 *a)
{
	*a -= i;
}

void env_atomic64_inc(env_atomic64 *a)
{
	++*a;
}

void env_atomic64_dec(env_atomic64 *a)
{
	--*a;
}

long env_atomic64_cmpxchg(env_atomic64 *a, long old, long new)
{
	long oldval = *a;
	if (oldval == old)
		*a = new;
	return oldval;
}

/* SPIN LOCKS */
void env_spinlock_init(env_spinlock *l)
{
	function_called();
	check_expected_ptr(l);
}

void env_spinlock_lock(env_spinlock *l)
{
	function_called();
	check_expected_ptr(l);
}

void env_spinlock_unlock(env_spinlock *l)
{
	function_called();
	check_expected_ptr(l);
}

/* RW LOCKS */
void env_rwlock_init(env_rwlock *l)
{
	function_called();
	check_expected_ptr(l);
}

void env_rwlock_read_lock(env_rwlock *l)
{
	function_called();
	check_expected_ptr(l);
}

void env_rwlock_read_unlock(env_rwlock *l)
{
	function_called();
	check_expected_ptr(l);
}

void env_rwlock_write_lock(env_rwlock *l)
{
	function_called();
	check_expected_ptr(l);
}

void env_rwlock_write_unlock(env_rwlock *l)
{
	function_called();
	check_expected_ptr(l);
}

/* BIT OPERATIONS */
void env_bit_set(int nr, volatile void *addr)
{
	char *byte = (char *) addr + (nr >> 3);
	char mask = 1 << (nr & 7);

	__sync_or_and_fetch(byte, mask);
}

void env_bit_clear(int nr, volatile void *addr)
{
	char *byte = (char *) addr + (nr >> 3);
	char mask = 1 << (nr & 7);

	mask = ~mask;
	__sync_and_and_fetch(byte, mask);
}

bool env_bit_test(int nr, const volatile unsigned long *addr)
{
	const char *byte = (char *) addr + (nr >> 3);
	char mask = 1 << (nr & 7);

	return !!(*byte & mask);
}

/* SCHEDULING */
void env_touch_softlockup_wd(void)
{
	function_called();
}

int env_in_interrupt(void)
{
	function_called();
	return mock();
}

uint64_t env_get_tick_count(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

uint64_t env_ticks_to_msecs(uint64_t j)
{
	return j;
}

uint64_t env_ticks_to_secs(uint64_t j)
{
	return j / 1000;
}

uint64_t env_secs_to_ticks(uint64_t j)
{
	return j * 1000;
}

/* STRING OPERATIONS */
int env_memset(void *dest, size_t count, int ch)
{
	memset(dest, ch, count);
	return 0;
}

int env_memcpy(void *dest, size_t destsz, const void * src, size_t count)
{
	if (destsz < count)
		memcpy(dest, src, destsz);
	else
		memcpy(dest, src, count);
	return 0;
}

int env_memcmp(const void *str1, size_t n1, const void *str2, size_t n2,
		int *diff)
{
	size_t n = n1 > n2 ? n2 : n1;

	*diff = memcmp(str1, str2, n);
	return 0;
}

int env_strncpy(char * dest, size_t destsz, const char *src, size_t count)
{
	if (destsz < count)
		strncpy(dest, src, destsz);
	else
		strncpy(dest, src, count);
	return 0;
}

size_t env_strnlen(const char *str, size_t strsz)
{
	return strlen(str);
}

void env_sort(void *base, size_t num, size_t size,
		int (*cmp_fn)(const void *, const void *),
		void (*swap_fn)(void *, void *, int size))
{
	qsort(base, num, size, cmp_fn);
}

int env_strncmp(const char * str1, const char * str2, size_t num)
{
	return strncmp(str1, str2, num);
}

/* TIME */
void env_msleep(uint64_t n)
{
}

/* CRC */
uint32_t env_crc32(uint32_t crc, uint8_t const *data, size_t len)
{
	function_called();
	check_expected(crc);
	check_expected(len);
	check_expected_ptr(data);
	return mock();
}
