/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */


#include "ocf/ocf.h"
#include "ocf_mngt_common.h"
#include "../ocf_priv.h"
#include "../ocf_core_priv.h"
#include "../ocf_ctx_priv.h"

void ocf_mngt_core_pool_init(ocf_ctx_t ctx)
{
	OCF_CHECK_NULL(ctx);
	INIT_LIST_HEAD(&ctx->core_pool.core_pool_head);
}

int ocf_mngt_core_pool_get_count(ocf_ctx_t ctx)
{
	int count;
	OCF_CHECK_NULL(ctx);
	env_mutex_lock(&ctx->lock);
	count = ctx->core_pool.core_pool_count;
	env_mutex_unlock(&ctx->lock);
	return count;
}

int ocf_mngt_core_pool_add(ocf_ctx_t ctx, ocf_uuid_t uuid, uint8_t type)
{
	ocf_data_obj_t obj;

	int result = 0;

	OCF_CHECK_NULL(ctx);

	result = ocf_ctx_data_obj_create(ctx, &obj, uuid, type);
	if (result)
		return result;

	result = ocf_data_obj_open(obj);
	if (result) {
		ocf_data_obj_deinit(obj);
		return result;
	}

	env_mutex_lock(&ctx->lock);
	list_add(&obj->core_pool_item, &ctx->core_pool.core_pool_head);
	ctx->core_pool.core_pool_count++;
	env_mutex_unlock(&ctx->lock);
	return result;
}

int ocf_mngt_core_pool_visit(ocf_ctx_t ctx,
		int (*visitor)(ocf_uuid_t, void *), void *visitor_ctx)
{
	int result = 0;
	ocf_data_obj_t sobj;

	OCF_CHECK_NULL(ctx);
	OCF_CHECK_NULL(visitor);

	env_mutex_lock(&ctx->lock);
	list_for_each_entry(sobj, &ctx->core_pool.core_pool_head,
			core_pool_item) {
		result = visitor(&sobj->uuid, visitor_ctx);
		if (result)
			break;
	}
	env_mutex_unlock(&ctx->lock);
	return result;
}

ocf_data_obj_t ocf_mngt_core_pool_lookup(ocf_ctx_t ctx, ocf_uuid_t uuid,
		ocf_data_obj_type_t type)
{
	ocf_data_obj_t sobj;

	OCF_CHECK_NULL(ctx);
	OCF_CHECK_NULL(uuid);
	OCF_CHECK_NULL(uuid->data);

	list_for_each_entry(sobj, &ctx->core_pool.core_pool_head,
			core_pool_item) {
		if (sobj->type == type && !env_strncmp(sobj->uuid.data,
			uuid->data, OCF_MIN(sobj->uuid.size, uuid->size))) {
			return sobj;
		}
	}

	return NULL;
}

void ocf_mngt_core_pool_remove(ocf_ctx_t ctx, ocf_data_obj_t obj)
{
	OCF_CHECK_NULL(ctx);
	OCF_CHECK_NULL(obj);
	env_mutex_lock(&ctx->lock);
	ctx->core_pool.core_pool_count--;
	list_del(&obj->core_pool_item);
	env_mutex_unlock(&ctx->lock);
	ocf_data_obj_deinit(obj);
}

void ocf_mngt_core_pool_close_and_remove(ocf_ctx_t ctx, ocf_data_obj_t obj)
{
	OCF_CHECK_NULL(ctx);
	OCF_CHECK_NULL(obj);
	ocf_data_obj_close(obj);
	ocf_mngt_core_pool_remove(ctx, obj);
}

void ocf_mngt_core_pool_deinit(ocf_ctx_t ctx)
{
	ocf_data_obj_t sobj, tobj;

	OCF_CHECK_NULL(ctx);

	list_for_each_entry_safe(sobj, tobj, &ctx->core_pool.core_pool_head,
			core_pool_item) {
		ocf_mngt_core_pool_close_and_remove(ctx, sobj);
	}
}
