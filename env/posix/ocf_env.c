/*
 * Copyright(c) 2019-2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_env.h"
#include <sched.h>
#include <execinfo.h>

/** @addtogroup ALLOCATOR
 * @{
 */

/**
 * @struct _env_allocator
 * @brief template allocator struct
 * @details contains:
 * <tt>char *name</tt> - memory pool ID unique name 
 * <tt>uint32_t item_size</tt> - size of specific item of memory pool
 * <tt>env_atomic count</tt> - number of currently allocated items in pool
 */
struct _env_allocator {
	char *name;
	uint32_t item_size;
	env_atomic count;
};

/**
 * @brief aligns allocator
 *
 * @param size bytes of memory to be allocated
 * @param fmt_name unique name
 * @param ... amount of currently allocated items in pool
 *
 * @retval nearest power of two equal or higher than size
 */
static inline size_t env_allocator_align(size_t size)
{
	if (size <= 2)
		return size;
	return (1ULL << 32) >> __builtin_clz(size - 1);
}

/**
 * @struct _env_allocator_item
 * @brief template allocator's item struct
 * @details contains:
 * <tt>uint32_t flags</tt> - memory management flags
 * <tt>uint32_t cpu</tt> - size of specific item of memory pool
 * <tt>char data[]</tt> - number of currently allocated items in pool
 */
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

env_allocator *env_allocator_create(uint32_t size, const char *fmt_name, ...)
{
	char name[OCF_ALLOCATOR_NAME_MAX] = { '\0' };
	int result, error = -1;
	va_list args;

	env_allocator *allocator = calloc(1, sizeof(*allocator));
	if (!allocator) {
		error = __LINE__;
		goto err;
	}

	allocator->item_size = size + sizeof(struct _env_allocator_item);

	/* Format allocator name */
	va_start(args, fmt_name);
	result = vsnprintf(name, sizeof(name), fmt_name, args);
	va_end(args);

	if ((result > 0) && (result < sizeof(name))) {
		allocator->name = strdup(name);

		if (!allocator->name) {
			error = __LINE__;
			goto err;
		}
	} else {
		/* Formated string name exceed max allowed size of name */
		error = __LINE__;
		goto err;
	}

	return allocator;

err:
	printf("Cannot create memory allocator, ERROR %d", error);
	env_allocator_destroy(allocator);

	return NULL;
}

void env_allocator_del(env_allocator *allocator, void *obj)
{
	struct _env_allocator_item *item =
		container_of(obj, struct _env_allocator_item, data);

	env_atomic_dec(&allocator->count);

	free(item);
}

void env_allocator_destroy(env_allocator *allocator)
{
	if (allocator) {
		if (env_atomic_read(&allocator->count)) {
			printf("Not all objects deallocated\n");
			ENV_WARN(true, OCF_PREFIX_SHORT" Cleanup problem\n");
		}

		free(allocator->name);
		free(allocator);
	}
}
/** @} */

/** @addtogroup DEBUGGING
 * @{
 */

/**
 * @def ENV_TRACE_DEPTH
 * @brief default depth of tracing
 */
#define ENV_TRACE_DEPTH	16

/**
 * @brief prints names of recently called functions to stdout
 */
void env_stack_trace(void)
{
	void *trace[ENV_TRACE_DEPTH];
	char **messages = NULL;
	int i, size;

	size = backtrace(trace, ENV_TRACE_DEPTH);
	messages = backtrace_symbols(trace, size);
	printf("[stack trace]>>>\n");
	for (i = 0; i < size; ++i)
		printf("%s\n", messages[i]);
	printf("<<<[stack trace]\n");
	free(messages);
}
/** @} */

/** @addtogroup CRC
 * @{
 */

uint32_t env_crc32(uint32_t crc, uint8_t const *data, size_t len)
{
	return crc32(crc, data, len);
}
/** @} */

/** @addtogroup EXECUTION_CONTEXTS
 * @{
 */

/**
 * @brief global pointer to execution context's mutex
 */
pthread_mutex_t *exec_context_mutex;

/**
 * @brief initiates execution context
 *
 * @bug assert if no contexts are available
 * @bug assert if can't allocate space for contexts' mutexes
 * @bug assert if contexts' mutexes can't be initiated
 * 
 */
static void __attribute__((constructor)) init_execution_context(void)
{
	unsigned count = env_get_execution_context_count();
	unsigned i;

	ENV_BUG_ON(count == 0);
	exec_context_mutex = malloc(count * sizeof(exec_context_mutex[0]));
	ENV_BUG_ON(exec_context_mutex == NULL);
	for (i = 0; i < count; i++)
		ENV_BUG_ON(pthread_mutex_init(&exec_context_mutex[i], NULL));
}

/**
 * @brief deinitiates execution context and frees its currently reserved space
 *
 * @bug assert if there's no available contexts
 * @bug assert if no space is currently allocated for contexts' mutexes
 * @bug assert if contexts' mutexes can't be destroyed
 * 
 */
static void __attribute__((destructor)) deinit_execution_context(void)
{
	unsigned count = env_get_execution_context_count();
	unsigned i;

	ENV_BUG_ON(count == 0);
	ENV_BUG_ON(exec_context_mutex == NULL);

	for (i = 0; i < count; i++)
		ENV_BUG_ON(pthread_mutex_destroy(&exec_context_mutex[i]));
	free(exec_context_mutex);
}

unsigned env_get_execution_context(void)
{
	unsigned cpu;

	cpu = sched_getcpu();
	cpu = (cpu == -1) ?  0 : cpu;

	ENV_BUG_ON(pthread_mutex_lock(&exec_context_mutex[cpu]));

	return cpu;
}

void env_put_execution_context(unsigned ctx)
{
	pthread_mutex_unlock(&exec_context_mutex[ctx]);
}

unsigned env_get_execution_context_count(void)
{
	int num = sysconf(_SC_NPROCESSORS_ONLN);

	return (num == -1) ? 0 : num;
}
/** @} */
