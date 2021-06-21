/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_CTX_PRIV_H__
#define __OCF_CTX_PRIV_H__

#include "ocf_env.h"
#include "ocf/ocf_ctx.h"
#include "ocf_logger_priv.h"
#include "ocf_volume_priv.h"
#include "utils/utils_journal.h"

#define OCF_VOLUME_TYPE_MAX 8

/**
 * @brief OCF main control structure
 */
struct ocf_ctx {
	struct ocf_volume_type *volume_type[OCF_VOLUME_TYPE_MAX];

	env_rmutex lock;
	struct ocf_logger logger;

	const struct ocf_ctx_ops *ops;
	struct {
		struct env_mpool *req;
		struct env_mpool *mio;
	} resources;
	struct list_head caches;
	struct {
		struct list_head core_pool_head;
		int core_pool_count;
	} core_pool;


	struct ocf_journal_schema journal_schema;

	const struct ocf_ctx_config *cfg;
	env_atomic ref_count;
};

#define ocf_log_prefix(ctx, lvl, prefix, fmt, ...) \
	 ocf_log_raw(&ctx->logger, lvl, prefix fmt, ##__VA_ARGS__)

#define ocf_log(ctx, lvl, fmt, ...) \
	ocf_log_prefix(ctx, lvl, "", fmt, ##__VA_ARGS__)

#define ocf_log_rl(ctx) \
	ocf_log_raw_rl(&ctx->logger, __func__)

#define ocf_log_stack_trace(ctx) \
	ocf_log_stack_trace_raw(&ctx->logger)

int ocf_ctx_register_volume_type_extended(ocf_ctx_t ctx, uint8_t type_id,
		const struct ocf_volume_properties *properties,
		const struct ocf_volume_extended *extended);

static inline ocf_persistent_meta_zone_t ctx_persistent_meta_init(ocf_ctx_t ctx,
		ocf_cache_t cache, size_t size, bool *loaded)
{
	return ctx->ops->persistent_meta.init(cache, size, loaded);
}

static inline int ctx_persistent_meta_deinit(ocf_ctx_t ctx,
		ocf_persistent_meta_zone_t zone)
{
	return ctx->ops->persistent_meta.deinit(zone);
}

static inline void *ctx_persistent_meta_alloc(ocf_ctx_t ctx,
		ocf_persistent_meta_zone_t zone, size_t size, int alloc_id, bool *load)
{
	return ctx->ops->persistent_meta.alloc(zone, size, alloc_id, load);
}

static inline int ctx_persistent_meta_free(ocf_ctx_t ctx,
		ocf_persistent_meta_zone_t zone, int alloc_id, void *ptr)
{
	return ctx->ops->persistent_meta.free(zone, alloc_id, ptr);
}
/**
 * @name Environment data buffer operations wrappers
 * @{
 */
static inline void *ctx_data_alloc(ocf_ctx_t ctx, uint32_t pages)
{
	return ctx->ops->data.alloc(pages);
}

static inline void ctx_data_free(ocf_ctx_t ctx, ctx_data_t *data)
{
	ctx->ops->data.free(data);
}

static inline int ctx_data_mlock(ocf_ctx_t ctx, ctx_data_t *data)
{
	return ctx->ops->data.mlock(data);
}

static inline void ctx_data_munlock(ocf_ctx_t ctx, ctx_data_t *data)
{
	ctx->ops->data.munlock(data);
}

static inline uint32_t ctx_data_rd(ocf_ctx_t ctx, void *dst,
		ctx_data_t *src, uint32_t size)
{
	return ctx->ops->data.read(dst, src, size);
}

static inline uint32_t ctx_data_wr(ocf_ctx_t ctx, ctx_data_t *dst,
		const void *src, uint32_t size)
{
	return ctx->ops->data.write(dst, src, size);
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
	return ctx->ops->data.zero(dst, size);
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
	return ctx->ops->data.seek(dst, seek, size);
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
	return ctx->ops->data.copy(dst, src, to, from, bytes);
}

static inline void ctx_data_secure_erase(ocf_ctx_t ctx, ctx_data_t *dst)
{
	return ctx->ops->data.secure_erase(dst);
}

static inline int ctx_cleaner_init(ocf_ctx_t ctx, ocf_cleaner_t cleaner)
{
	return ctx->ops->cleaner.init(cleaner);
}

static inline void ctx_cleaner_stop(ocf_ctx_t ctx, ocf_cleaner_t cleaner)
{
	ctx->ops->cleaner.stop(cleaner);
}

static inline void ctx_cleaner_kick(ocf_ctx_t ctx, ocf_cleaner_t cleaner)
{
	ctx->ops->cleaner.kick(cleaner);
}

static inline struct ocf_journal_schema *ctx_get_journal_schema(ocf_ctx_t ctx)
{
	return &ctx->journal_schema;

}

/**
 * @}
 */

#endif /* __OCF_CTX_PRIV_H__ */
