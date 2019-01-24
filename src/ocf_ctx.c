/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_ctx_priv.h"
#include "ocf_priv.h"
#include "ocf_data_obj_priv.h"
#include "ocf_utils.h"
#include "ocf_logger_priv.h"
#include "ocf_core_priv.h"

/*
 *
 */
int ocf_ctx_register_data_obj_type(ocf_ctx_t ctx, uint8_t type_id,
		const struct ocf_data_obj_properties *properties)
{
	int result = 0;

	if (!ctx || !properties)
		return -EINVAL;

	env_mutex_lock(&ctx->lock);

	if (type_id >= OCF_DATA_OBJ_TYPE_MAX || ctx->data_obj_type[type_id]) {
		env_mutex_unlock(&ctx->lock);
		result = -EINVAL;
		goto err;
	}

	ocf_data_obj_type_init(&ctx->data_obj_type[type_id], properties);
	if (!ctx->data_obj_type[type_id])
		result = -EINVAL;

	env_mutex_unlock(&ctx->lock);

	if (result)
		goto err;

	ocf_log(ctx, log_debug, "'%s' data object operations registered\n",
			properties->name);
	return 0;

err:
	ocf_log(ctx, log_err, "Failed to register data object operations '%s'",
			properties->name);
	return result;
}

/*
 *
 */
void ocf_ctx_unregister_data_obj_type(ocf_ctx_t ctx, uint8_t type_id)
{
	OCF_CHECK_NULL(ctx);

	env_mutex_lock(&ctx->lock);

	if (type_id < OCF_DATA_OBJ_TYPE_MAX && ctx->data_obj_type[type_id]) {
		ocf_data_obj_type_deinit(ctx->data_obj_type[type_id]);
		ctx->data_obj_type[type_id] = NULL;
	}

	env_mutex_unlock(&ctx->lock);
}

/*
 *
 */
ocf_data_obj_type_t ocf_ctx_get_data_obj_type(ocf_ctx_t ctx, uint8_t type_id)
{
	OCF_CHECK_NULL(ctx);

	if (type_id >= OCF_DATA_OBJ_TYPE_MAX)
		return NULL;

	return ctx->data_obj_type[type_id];
}

/*
 *
 */
int ocf_ctx_get_data_obj_type_id(ocf_ctx_t ctx, ocf_data_obj_type_t type)
{
	int i;

	OCF_CHECK_NULL(ctx);

	for (i = 0; i < OCF_DATA_OBJ_TYPE_MAX; ++i) {
		if (ctx->data_obj_type[i] == type)
			return i;
	}

	return -1;
}

/*
 *
 */
int ocf_ctx_data_obj_create(ocf_ctx_t ctx, ocf_data_obj_t *obj,
		struct ocf_data_obj_uuid *uuid, uint8_t type_id)
{
	OCF_CHECK_NULL(ctx);

	if (type_id >= OCF_DATA_OBJ_TYPE_MAX)
		return -EINVAL;

	return ocf_dobj_create(obj, ctx->data_obj_type[type_id], uuid);
}

/*
 *
 */
int ocf_ctx_init(ocf_ctx_t *ctx, const struct ocf_ctx_config *cfg)
{
	ocf_ctx_t ocf_ctx;
	int ret;

	OCF_CHECK_NULL(ctx);
	OCF_CHECK_NULL(cfg);

	ocf_ctx = env_zalloc(sizeof(*ocf_ctx), ENV_MEM_NORMAL);
	if (!ocf_ctx)
		return -ENOMEM;

	INIT_LIST_HEAD(&ocf_ctx->caches);
	ret = env_mutex_init(&ocf_ctx->lock);
	if (ret)
		goto err_ctx;

	ocf_ctx->ops = &cfg->ops;
	ocf_ctx->cfg = cfg;

	ocf_logger_init(&ocf_ctx->logger, &cfg->ops.logger, cfg->logger_priv);

	ret = ocf_logger_open(&ocf_ctx->logger);
	if (ret)
		goto err_ctx;

	ret = ocf_utils_init(ocf_ctx);
	if (ret)
		goto err_logger;

	ret = ocf_core_data_obj_type_init(ocf_ctx);
	if (ret)
		goto err_utils;

	*ctx = ocf_ctx;

	return 0;

err_utils:
	ocf_utils_deinit(ocf_ctx);
err_logger:
	ocf_logger_close(&ocf_ctx->logger);
err_ctx:
	env_free(ocf_ctx);
	return ret;
}

/*
 *
 */
int ocf_ctx_exit(ocf_ctx_t ctx)
{
	int result = 0;

	OCF_CHECK_NULL(ctx);

	/* Check if caches are setup */
	env_mutex_lock(&ctx->lock);
	if (!list_empty(&ctx->caches))
		result = -EEXIST;
	env_mutex_unlock(&ctx->lock);
	if (result)
		return result;

	ocf_core_data_obj_type_deinit(ctx);

	ocf_utils_deinit(ctx);
	ocf_logger_close(&ctx->logger);
	env_free(ctx);

	return 0;
}
