/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <execinfo.h>
#include <ocf/ocf.h>
#include "ocf_env.h"
#include "data.h"
#include "dobj.h"
#include "ctx.h"

#define PAGE_SIZE 4096

/*
 * Allocate structure representing data for io operations.
 */
ctx_data_t *ctx_data_alloc(uint32_t pages)
{
	struct dobj_data *data;

	data = malloc(sizeof(*data));
	data->ptr = malloc(pages * PAGE_SIZE);
	data->offset = 0;

	return data;
}

/*
 * Free data structure.
 */
void ctx_data_free(ctx_data_t *ctx_data)
{
	struct dobj_data *data = ctx_data;

	if (!data)
		return;

	free(data->ptr);
	free(data);
}

/*
 * This function is supposed to set protection of data pages against swapping.
 * Can be non-implemented if not needed.
 */
static int ctx_data_mlock(ctx_data_t *ctx_data)
{
	return 0;
}

/*
 * Stop protecting data pages against swapping.
 */
static void ctx_data_munlock(ctx_data_t *ctx_data)
{
}

/*
 * Read data into flat memory buffer.
 */
static uint32_t ctx_data_rd(void *dst, ctx_data_t *src, uint32_t size)
{
	struct dobj_data *data = src;

	memcpy(dst, data->ptr + data->offset, size);

	return size;
}

/*
 * Write data from flat memory buffer.
 */
static uint32_t ctx_data_wr(ctx_data_t *dst, const void *src, uint32_t size)
{
	struct dobj_data *data = dst;

	memcpy(data->ptr + data->offset, src, size);

	return size;
}

/*
 * Fill data with zeros.
 */
static uint32_t ctx_data_zero(ctx_data_t *dst, uint32_t size)
{
	struct dobj_data *data = dst;

	memset(data->ptr + data->offset, 0, size);

	return size;
}

/*
 * Perform seek operation on data.
 */
static uint32_t ctx_data_seek(ctx_data_t *dst, ctx_data_seek_t seek,
		uint32_t offset)
{
	struct dobj_data *data = dst;

	switch (seek) {
	case ctx_data_seek_begin:
		data->offset = offset;
		break;
	case ctx_data_seek_current:
		data->offset += offset;
		break;
	}

	return offset;
}

/*
 * Copy data from one structure to another.
 */
static uint64_t ctx_data_cpy(ctx_data_t *dst, ctx_data_t *src,
		uint64_t to, uint64_t from, uint64_t bytes)
{
	struct dobj_data *data_dst = dst;
	struct dobj_data *data_src = src;

	memcpy(data_dst->ptr + to, data_src->ptr + from, bytes);

	return bytes;
}

/*
 * Perform secure erase of data (e.g. fill pages with zeros).
 * Can be left non-implemented if not needed.
 */
static void ctx_data_secure_erase(ctx_data_t *ctx_data)
{
}

/*
 * Initialize queue thread. To keep this example simple we handle queues
 * synchronously, thus it's left non-implemented.
 */
static int ctx_queue_init(ocf_queue_t q)
{
	return 0;
}

/*
 * Trigger queue asynchronously. Made synchronous for simplicity.
 */
static inline void ctx_queue_kick_async(ocf_queue_t q)
{
	ocf_queue_run(q);
}

/*
 * Trigger queue synchronously. May be implemented as asynchronous as well,
 * but in some environments kicking queue synchronously may reduce latency,
 * so to take advantage of such situations OCF call synchronous variant of
 * queue kick callback where possible.
 */
static void ctx_queue_kick_sync(ocf_queue_t q)
{
	ocf_queue_run(q);
}

/*
 * Stop queue thread. To keep this example simple we handle queues
 * synchronously, thus it's left non-implemented.
 */
static void ctx_queue_stop(ocf_queue_t q)
{
}

/*
 * Initialize cleaner thread. Cleaner thread is left non-implemented,
 * to keep this example as simple as possible.
 */
static int ctx_cleaner_init(ocf_cleaner_t c)
{
	return 0;
}

/*
 * Stop cleaner thread. Cleaner thread is left non-implemented, to keep
 * this example as simple as possible.
 */
static void ctx_cleaner_stop(ocf_cleaner_t c)
{
}

/*
 * Initialize metadata updater thread. Metadata updater thread is left
 * non-implemented to keep this example as simple as possible.
 */
static int ctx_metadata_updater_init(ocf_metadata_updater_t mu)
{
	return 0;
}

/*
 * Kick metadata updater thread. Metadata updater thread is left
 * non-implemented to keep this example as simple as possible.
 */
static void ctx_metadata_updater_kick(ocf_metadata_updater_t mu)
{
}

/*
 * Stop metadata updater thread. Metadata updater thread is left
 * non-implemented to keep this example as simple as possible.
 */
static void ctx_metadata_updater_stop(ocf_metadata_updater_t mu)
{
}

/*
 * This structure describes context ops. They are splitted into few categories:
 * - data ops, providing context specific data handing interface,
 * - queue ops, providing interface for starting, stoping and kicking
 *   queue thread in both synchronous and asynchronous way,
 * - cleaner ops, providing interface to start and stop clener thread,
 * - metadata updater ops, providing interface for starting, stoping
 *   and kicking metadata updater thread.
 */
static const struct ocf_ctx_ops ctx_ops = {
	.name = "OCF Example",

	.data_alloc = ctx_data_alloc,
	.data_free = ctx_data_free,
	.data_mlock = ctx_data_mlock,
	.data_munlock = ctx_data_munlock,
	.data_rd = ctx_data_rd,
	.data_wr = ctx_data_wr,
	.data_zero = ctx_data_zero,
	.data_seek = ctx_data_seek,
	.data_cpy = ctx_data_cpy,
	.data_secure_erase = ctx_data_secure_erase,

	.queue_init = ctx_queue_init,
	.queue_kick_sync = ctx_queue_kick_sync,
	.queue_kick = ctx_queue_kick_async,
	.queue_stop = ctx_queue_stop,

	.cleaner_init = ctx_cleaner_init,
	.cleaner_stop = ctx_cleaner_stop,

	.metadata_updater_init = ctx_metadata_updater_init,
	.metadata_updater_kick = ctx_metadata_updater_kick,
	.metadata_updater_stop = ctx_metadata_updater_stop,
};

/*
 * Function prividing interface for printing to log used by OCF internals.
 * It can handle differently messages at varous log levels.
 */
static int ctx_log_printf(const struct ocf_logger *logger,
		ocf_logger_lvl_t lvl, const char *fmt, va_list args)
{
	FILE *lfile = stdout;

	if (lvl > log_info)
		return 0;

	if (lvl <= log_warn)
		lfile = stderr;

	return vfprintf(lfile, fmt, args);
}

#define CTX_LOG_TRACE_DEPTH	16

/*
 * Function prividing interface for printing current stack. Used for debugging,
 * and for providing additional information in log in case of errors.
 */
static int ctx_log_dump_stack(const struct ocf_logger *logger)
{
	void *trace[CTX_LOG_TRACE_DEPTH];
	char **messages = NULL;
	int i, size;

	size = backtrace(trace, CTX_LOG_TRACE_DEPTH);
	messages = backtrace_symbols(trace, size);
	printf("[stack trace]>>>\n");
	for (i = 0; i < size; ++i)
		printf("%s\n", messages[i]);
	printf("<<<[stack trace]\n");
	free(messages);

	return 0;
}

/*
 * Structure containng logger ops.
 */
static const struct ocf_logger logger = {
	.printf = ctx_log_printf,
	.dump_stack = ctx_log_dump_stack,
};

/*
 * Function initializing context. Prepares context, sets logger and
 * registers data object type.
 */
int ctx_init(ocf_ctx_t *ctx)
{
	int ret;

	ret = ocf_ctx_init(ctx, &ctx_ops);
	if (ret)
		return ret;

	ocf_ctx_set_logger(*ctx, &logger);

	ret = dobj_init(*ctx);
	if (ret) {
		dobj_cleanup(*ctx);
		return ret;
	}

	return 0;
}

/*
 * Function cleaning up context. Unregisters data object type and
 * deinitializes context.
 */
void ctx_cleanup(ocf_ctx_t ctx)
{
	dobj_cleanup(ctx);
	ocf_ctx_exit(ctx);
}
