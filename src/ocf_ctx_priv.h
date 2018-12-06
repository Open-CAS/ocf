/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_CTX_PRIV_H__
#define __OCF_CTX_PRIV_H__

#include "ocf_env.h"
#include "ocf/ocf_logger.h"
#include "ocf_logger_priv.h"

#define OCF_DATA_OBJ_TYPE_MAX 8

/**
 * @brief OCF main control structure
 */
struct ocf_ctx {
	const struct ocf_ctx_ops *ctx_ops;
	const struct ocf_logger *logger;
	struct ocf_data_obj_type *data_obj_type[OCF_DATA_OBJ_TYPE_MAX];
	env_mutex lock;
	struct list_head caches;
	struct {
		struct list_head core_pool_head;
		int core_pool_count;
	} core_pool;

	struct {
		struct ocf_rq_allocator *rq;
		env_allocator *core_io_allocator;
	} resources;
};

#define ocf_log_prefix(ctx, lvl, prefix, fmt, ...) \
	ocf_log_raw(ctx->logger, lvl, prefix fmt, ##__VA_ARGS__)

#define ocf_log(ctx, lvl, fmt, ...) \
	ocf_log_prefix(ctx, lvl, "", fmt, ##__VA_ARGS__)

#define ocf_log_rl(ctx) \
	ocf_log_raw_rl(ctx->logger, __func__)

#define ocf_log_stack_trace(ctx) \
	ocf_log_stack_trace_raw(ctx->logger)

/**
 * @name Environment data buffer operations wrappers
 * @{
 */
static inline void *ctx_data_alloc(ocf_ctx_t ctx, uint32_t pages)
{
	return ctx->ctx_ops->data_alloc(pages);
}

static inline void ctx_data_free(ocf_ctx_t ctx, ctx_data_t *data)
{
	ctx->ctx_ops->data_free(data);
}

static inline int ctx_data_mlock(ocf_ctx_t ctx, ctx_data_t *data)
{
	return ctx->ctx_ops->data_mlock(data);
}

static inline void ctx_data_munlock(ocf_ctx_t ctx, ctx_data_t *data)
{
	ctx->ctx_ops->data_munlock(data);
}

static inline uint32_t ctx_data_rd(ocf_ctx_t ctx, void *dst,
		ctx_data_t *src, uint32_t size)
{
	return ctx->ctx_ops->data_rd(dst, src, size);
}

static inline uint32_t ctx_data_wr(ocf_ctx_t ctx, ctx_data_t *dst,
		const void *src, uint32_t size)
{
	return ctx->ctx_ops->data_wr(dst, src, size);
}

static inline void ctx_data_rd_check(ocf_ctx_t ctx, void *dst,
		ctx_data_t *src, uint32_t size)
{
	uint32_t read = ctx_data_rd(ctx, dst, src, size);

	ENV_BUG_ON(read != size);
}

static inline void ctx_data_wr_check(ocf_ctx_t ctx, ctx_data_t *dst,
		const void *src, uint32_t size)
{
	uint32_t written = ctx_data_wr(ctx, dst, src, size);

	ENV_BUG_ON(written != size);
}

static inline uint32_t ctx_data_zero(ocf_ctx_t ctx, ctx_data_t *dst,
		uint32_t size)
{
	return ctx->ctx_ops->data_zero(dst, size);
}

static inline void ctx_data_zero_check(ocf_ctx_t ctx, ctx_data_t *dst,
		uint32_t size)
{
	uint32_t zerored = ctx_data_zero(ctx, dst, size);

	ENV_BUG_ON(zerored != size);
}

static inline uint32_t ctx_data_seek(ocf_ctx_t ctx, ctx_data_t *dst,
		ctx_data_seek_t seek, uint32_t size)
{
	return ctx->ctx_ops->data_seek(dst, seek, size);
}

static inline void ctx_data_seek_check(ocf_ctx_t ctx, ctx_data_t *dst,
		ctx_data_seek_t seek, uint32_t size)
{
	uint32_t bytes = ctx_data_seek(ctx, dst, seek, size);

	ENV_BUG_ON(bytes != size);
}

static inline uint64_t ctx_data_cpy(ocf_ctx_t ctx, ctx_data_t *dst, ctx_data_t *src,
		uint64_t to, uint64_t from, uint64_t bytes)
{
	return ctx->ctx_ops->data_cpy(dst, src, to, from, bytes);
}

static inline void ctx_data_secure_erase(ocf_ctx_t ctx, ctx_data_t *dst)
{
	return ctx->ctx_ops->data_secure_erase(dst);
}

static inline int ctx_queue_init(ocf_ctx_t ctx, ocf_queue_t queue)
{
	return ctx->ctx_ops->queue_init(queue);
}

static inline void ctx_queue_kick(ocf_ctx_t ctx, ocf_queue_t queue,
		bool allow_sync)
{
	if (allow_sync && ctx->ctx_ops->queue_kick_sync)
		ctx->ctx_ops->queue_kick_sync(queue);
	else
		ctx->ctx_ops->queue_kick(queue);
}

static inline void ctx_queue_stop(ocf_ctx_t ctx, ocf_queue_t queue)
{
	ctx->ctx_ops->queue_stop(queue);
}

static inline int ctx_cleaner_init(ocf_ctx_t ctx, ocf_cleaner_t cleaner)
{
	return ctx->ctx_ops->cleaner_init(cleaner);
}

static inline void ctx_cleaner_stop(ocf_ctx_t ctx, ocf_cleaner_t cleaner)
{
	ctx->ctx_ops->cleaner_stop(cleaner);
}

static inline int ctx_metadata_updater_init(ocf_ctx_t ctx,
		ocf_metadata_updater_t mu)
{
	return ctx->ctx_ops->metadata_updater_init(mu);
}

static inline void ctx_metadata_updater_kick(ocf_ctx_t ctx,
		ocf_metadata_updater_t mu)
{
	ctx->ctx_ops->metadata_updater_kick(mu);
}

static inline void ctx_metadata_updater_stop(ocf_ctx_t ctx,
		ocf_metadata_updater_t mu)
{
	ctx->ctx_ops->metadata_updater_stop(mu);
}

/**
 * @}
 */

#endif /* __OCF_CTX_PRIV_H__ */
