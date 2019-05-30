/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_ctx_priv.h"
#include "ocf_priv.h"
#include "ocf_volume_priv.h"
#include "ocf_request.h"
#include "ocf_logger_priv.h"
#include "ocf_core_priv.h"
#include "mngt/ocf_mngt_core_pool_priv.h"

/*
 *
 */
int ocf_ctx_register_volume_type(ocf_ctx_t ctx, uint8_t type_id,
		const struct ocf_volume_properties *properties)
{
	int result = 0;

	if (!ctx || !properties)
		return -EINVAL;

	env_mutex_lock(&ctx->lock);

	if (type_id >= OCF_VOLUME_TYPE_MAX || ctx->volume_type[type_id]) {
		env_mutex_unlock(&ctx->lock);
		result = -EINVAL;
		goto err;
	}

	ocf_volume_type_init(&ctx->volume_type[type_id], properties);
	if (!ctx->volume_type[type_id])
		result = -EINVAL;

	env_mutex_unlock(&ctx->lock);

	if (result)
		goto err;

	ocf_log(ctx, log_debug, "'%s' volume operations registered\n",
			properties->name);
	return 0;

err:
	ocf_log(ctx, log_err, "Failed to register volume operations '%s'\n",
			properties->name);
	return result;
}

/*
 *
 */
void ocf_ctx_unregister_volume_type(ocf_ctx_t ctx, uint8_t type_id)
{
	OCF_CHECK_NULL(ctx);

	env_mutex_lock(&ctx->lock);

	if (type_id < OCF_VOLUME_TYPE_MAX && ctx->volume_type[type_id]) {
		ocf_volume_type_deinit(ctx->volume_type[type_id]);
		ctx->volume_type[type_id] = NULL;
	}

	env_mutex_unlock(&ctx->lock);
}

/*
 *
 */
ocf_volume_type_t ocf_ctx_get_volume_type(ocf_ctx_t ctx, uint8_t type_id)
{
	OCF_CHECK_NULL(ctx);

	if (type_id >= OCF_VOLUME_TYPE_MAX)
		return NULL;

	return ctx->volume_type[type_id];
}

/*
 *
 */
int ocf_ctx_get_volume_type_id(ocf_ctx_t ctx, ocf_volume_type_t type)
{
	int i;

	OCF_CHECK_NULL(ctx);

	for (i = 0; i < OCF_VOLUME_TYPE_MAX; ++i) {
		if (ctx->volume_type[i] == type)
			return i;
	}

	return -1;
}

/*
 *
 */
int ocf_ctx_volume_create(ocf_ctx_t ctx, ocf_volume_t *volume,
		struct ocf_volume_uuid *uuid, uint8_t type_id)
{
	OCF_CHECK_NULL(ctx);

	if (type_id >= OCF_VOLUME_TYPE_MAX)
		return -EINVAL;

	return ocf_volume_create(volume, ctx->volume_type[type_id], uuid);
}

/*
 *
 */
int ocf_ctx_create(ocf_ctx_t *ctx, const struct ocf_ctx_config *cfg)
{
	ocf_ctx_t ocf_ctx;
	int ret;

	OCF_CHECK_NULL(ctx);
	OCF_CHECK_NULL(cfg);

	ocf_ctx = env_zalloc(sizeof(*ocf_ctx), ENV_MEM_NORMAL);
	if (!ocf_ctx)
		return -ENOMEM;

	INIT_LIST_HEAD(&ocf_ctx->caches);
	env_atomic_set(&ocf_ctx->ref_count, 1);
	ret = env_mutex_init(&ocf_ctx->lock);
	if (ret)
		goto err_ctx;

	ocf_ctx->ops = &cfg->ops;
	ocf_ctx->cfg = cfg;

	ocf_logger_init(&ocf_ctx->logger, &cfg->ops.logger, cfg->logger_priv);

	ret = ocf_logger_open(&ocf_ctx->logger);
	if (ret)
		goto err_ctx;

	ret = ocf_req_allocator_init(ocf_ctx);
	if (ret)
		goto err_logger;

	ret = ocf_core_volume_type_init(ocf_ctx);
	if (ret)
		goto err_utils;

	ocf_mngt_core_pool_init(ocf_ctx);

	*ctx = ocf_ctx;

	return 0;

err_utils:
	ocf_req_allocator_deinit(ocf_ctx);
err_logger:
	ocf_logger_close(&ocf_ctx->logger);
err_ctx:
	env_free(ocf_ctx);
	return ret;
}

/*
 *
 */
void ocf_ctx_get(ocf_ctx_t ctx)
{
	OCF_CHECK_NULL(ctx);

	env_atomic_inc(&ctx->ref_count);
}

/*
 *
 */
void ocf_ctx_put(ocf_ctx_t ctx)
{
	OCF_CHECK_NULL(ctx);

	if (env_atomic_dec_return(&ctx->ref_count))
		return;

	env_mutex_lock(&ctx->lock);
	ENV_BUG_ON(!list_empty(&ctx->caches));
	env_mutex_unlock(&ctx->lock);

	ocf_mngt_core_pool_deinit(ctx);
	ocf_core_volume_type_deinit(ctx);
	ocf_req_allocator_deinit(ctx);
	ocf_logger_close(&ctx->logger);
	env_free(ctx);
}
