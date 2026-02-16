/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024-2025 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_priv.h"
#include "ocf_volume_priv.h"
#include "ocf_core_priv.h"
#include "ocf_request.h"
#include "ocf_env_refcnt.h"
#include "ocf_io_priv.h"
#include "ocf_env.h"

int ocf_uuid_set_str(ocf_uuid_t uuid, char *str)
{
        size_t len = env_strnlen(str, OCF_VOLUME_UUID_MAX_SIZE);

        if (len >= OCF_VOLUME_UUID_MAX_SIZE)
                return -OCF_ERR_INVAL;

        uuid->data = str;
        uuid->size = len + 1;

        return 0;
}

/* *** Bottom interface *** */

/*
 * Volume type
 */

int ocf_volume_type_init(struct ocf_volume_type **type, ocf_ctx_t ctx,
		const struct ocf_volume_properties *properties,
		const struct ocf_volume_extended *extended)
{
	const struct ocf_volume_ops *ops = &properties->ops;
	ocf_io_allocator_type_t allocator_type;
	struct ocf_volume_type *new_type;
	int ret;

	if (!ops->open || !ops->close || !ops->get_max_io_size ||
			!ops->get_length) {
		return -OCF_ERR_INVAL;
	}

	if (properties->caps.atomic_writes && !ops->submit_metadata)
		return -OCF_ERR_INVAL;

	new_type = env_zalloc(sizeof(**type), ENV_MEM_NORMAL);
	if (!new_type)
		return -OCF_ERR_NO_MEM;

	if (extended && extended->allocator_type)
		allocator_type = extended->allocator_type;
	else
		allocator_type = ocf_io_allocator_get_type_default();

	ret = ocf_io_allocator_init(&new_type->allocator, allocator_type,
			properties->name);
	if (ret)
		goto err;

	new_type->properties = properties;
	new_type->owner = ctx;

	*type = new_type;

	return 0;

err:
	env_free(new_type);
	return ret;
}

void ocf_volume_type_deinit(struct ocf_volume_type *type)
{
	if (type->properties->deinit)
		type->properties->deinit();

	ocf_io_allocator_deinit(&type->allocator);
	env_free(type);
}

/*
 * Volume frontend API
 */

int ocf_volume_init(ocf_volume_t volume, ocf_volume_type_t type,
		struct ocf_volume_uuid *uuid, bool uuid_copy)
{
	uint32_t priv_size;
	void *data;
	int ret;

	if (!volume || !type)
		return -OCF_ERR_INVAL;

	if (uuid && uuid->size > OCF_VOLUME_UUID_MAX_SIZE)
		return -OCF_ERR_INVAL;

	priv_size = type->properties->volume_priv_size;
	volume->priv = env_zalloc(priv_size, ENV_MEM_NORMAL);
	if (!volume->priv)
		return -OCF_ERR_NO_MEM;

	volume->opened = false;
	volume->type = type;

	volume->uuid.size = 0;
	volume->uuid.data = NULL;
	volume->uuid_copy = false;

	ret = env_refcnt_init(&volume->refcnt, "volume", sizeof("volume"));
	if (ret)
		goto err1;

	env_refcnt_freeze(&volume->refcnt);

	if (!uuid)
		goto on_init;

	volume->uuid_copy = uuid_copy;

	if (uuid_copy) {
		data = env_vmalloc(uuid->size);
		if (!data) {
			ret = -OCF_ERR_NO_MEM;
			goto err2;
		}

		volume->uuid.data = data;

		ret = env_memcpy(data, uuid->size, uuid->data, uuid->size);
		if (ret) {
			ret = -OCF_ERR_INVAL;
			goto err3;
		}
	} else {
		volume->uuid.data = uuid->data;
	}

	volume->uuid.size = uuid->size;

on_init:
	if (volume->type->properties->ops.on_init) {
		ret = volume->type->properties->ops.on_init(volume);
		if (ret)
			goto err3;
	}

	return 0;

err3:
	if (volume->uuid_copy && volume->uuid.data)
		env_vfree(volume->uuid.data);
	volume->uuid.data = NULL;
	volume->uuid.size = 0;
err2:
	env_refcnt_unfreeze(&volume->refcnt);
	env_refcnt_deinit(&volume->refcnt);
err1:
	env_free(volume->priv);
	volume->priv = NULL;
	return ret;
}

void ocf_volume_deinit(ocf_volume_t volume)
{
	OCF_CHECK_NULL(volume);

	if (volume->type && volume->type->properties->ops.on_deinit)
		volume->type->properties->ops.on_deinit(volume);

	env_free(volume->priv);
	volume->priv = NULL;
	volume->type = NULL;
	env_refcnt_deinit(&volume->refcnt);

	if (volume->uuid_copy && volume->uuid.data) {
		env_vfree(volume->uuid.data);
		volume->uuid.data = NULL;
		volume->uuid.size = 0;
	}
}

void ocf_volume_move(ocf_volume_t volume, ocf_volume_t from)
{
	OCF_CHECK_NULL(volume);
	OCF_CHECK_NULL(from);

	ENV_BUG_ON(!env_refcnt_zeroed(&volume->refcnt));
	ENV_BUG_ON(!env_refcnt_zeroed(&from->refcnt));

	env_free(volume->priv);
	if (volume->uuid_copy && volume->uuid.data)
		env_vfree(volume->uuid.data);

	/* volume->refcnt is not reinitialized */

	volume->opened = from->opened;
	volume->type = from->type;
	volume->uuid = from->uuid;
	volume->uuid_copy = from->uuid_copy;
	volume->priv = from->priv;
	volume->cache = from->cache;
	volume->features = from->features;

	/*
	 * Deinitialize original volume without freeing resources.
	 */
	from->opened = false;
	from->priv = NULL;
	from->uuid.data = NULL;
	from->type = NULL;
}

int ocf_volume_create(ocf_volume_t *volume, ocf_volume_type_t type,
		struct ocf_volume_uuid *uuid)
{
	ocf_volume_t tmp_volume;
	int ret;

	OCF_CHECK_NULL(volume);

	tmp_volume = env_zalloc(sizeof(*tmp_volume), ENV_MEM_NORMAL);
	if (!tmp_volume)
		return -OCF_ERR_NO_MEM;

	ret = ocf_volume_init(tmp_volume, type, uuid, true);
	if (ret) {
		env_free(tmp_volume);
		return ret;
	}

	*volume = tmp_volume;

	return 0;
}

void ocf_volume_destroy(ocf_volume_t volume)
{
	OCF_CHECK_NULL(volume);

	ocf_volume_deinit(volume);
	env_free(volume);
}

ocf_volume_type_t ocf_volume_get_type(ocf_volume_t volume)
{
	OCF_CHECK_NULL(volume);

	return volume->type;
}

const struct ocf_volume_uuid *ocf_volume_get_uuid(ocf_volume_t volume)
{
	OCF_CHECK_NULL(volume);

	return &volume->uuid;
}

void ocf_volume_set_uuid(ocf_volume_t volume, const struct ocf_volume_uuid *uuid)
{
	OCF_CHECK_NULL(volume);

	if (volume->uuid_copy && volume->uuid.data)
		env_vfree(volume->uuid.data);

	volume->uuid.data = uuid->data;
	volume->uuid.size = uuid->size;
}

void *ocf_volume_get_priv(ocf_volume_t volume)
{
	return volume->priv;
}

ocf_cache_t ocf_volume_get_cache(ocf_volume_t volume)
{
	OCF_CHECK_NULL(volume);

	return volume->cache;
}

int ocf_volume_is_atomic(ocf_volume_t volume)
{
	return volume->type->properties->caps.atomic_writes;
}

bool ocf_volume_is_composite(ocf_volume_t volume)
{
	return volume->type->properties->caps.composite_volume;
}

ocf_io_t ocf_volume_new_io(ocf_volume_t volume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir,
		uint32_t io_class, uint64_t flags)
{
	return ocf_io_new(volume, queue, addr, bytes, dir, io_class, flags);
}

static void ocf_volume_req_forward_end(struct ocf_request *req, int error)
{
	ocf_io_end_func(req, error);
}

void ocf_volume_submit_io(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	ocf_volume_t volume = ocf_io_get_volume(io);

	if (!volume->opened) {
		ocf_io_end_func(io, -OCF_ERR_IO);
		return;
	}

	if (likely(volume->type->properties->ops.submit_io)) {
		volume->type->properties->ops.submit_io(io);
	} else {
		ocf_req_forward_volume_init(req, ocf_volume_req_forward_end);
		ocf_req_forward_volume_io(req, volume, req->rw, req->addr,
				req->bytes, req->offset);
	}
}

void ocf_volume_submit_flush(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	ocf_volume_t volume = ocf_io_get_volume(io);

	if (!volume->opened) {
		ocf_io_end_func(io, -OCF_ERR_IO);
		return;
	}

	if (likely(volume->type->properties->ops.submit_flush)) {
		volume->type->properties->ops.submit_flush(io);
	} else {
		ocf_req_forward_volume_init(req, ocf_volume_req_forward_end);
		ocf_req_forward_volume_flush(req, volume);
	}
}

void ocf_volume_submit_discard(ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	ocf_volume_t volume = ocf_io_get_volume(io);

	if (!volume->opened) {
		ocf_io_end_func(io, -OCF_ERR_IO);
		return;
	}

	if (likely(volume->type->properties->ops.submit_discard)) {
		volume->type->properties->ops.submit_discard(io);
	} else {
		ocf_req_forward_volume_init(req, ocf_volume_req_forward_end);
		ocf_req_forward_volume_discard(req, volume,
				req->addr, req->bytes);
	}
}

void ocf_volume_forward_io(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset)
{
	ENV_BUG_ON(!volume->type->properties->ops.forward_io);

	if (!volume->opened) {
		ocf_forward_end(token, -OCF_ERR_IO);
		return;
	}

	volume->type->properties->ops.forward_io(volume, token,
			dir, addr, bytes, offset);
}

void ocf_volume_forward_flush(ocf_volume_t volume, ocf_forward_token_t token)
{
	ENV_BUG_ON(!volume->type->properties->ops.forward_flush);

	if (!volume->opened) {
		ocf_forward_end(token, -OCF_ERR_IO);
		return;
	}

	volume->type->properties->ops.forward_flush(volume, token);
}

void ocf_volume_forward_discard(ocf_volume_t volume, ocf_forward_token_t token,
		uint64_t addr, uint64_t bytes)
{
	ENV_BUG_ON(!volume->type->properties->ops.forward_discard);

	if (!volume->opened) {
		ocf_forward_end(token, -OCF_ERR_IO);
		return;
	}

	volume->type->properties->ops.forward_discard(volume, token,
			addr, bytes);
}

void ocf_volume_forward_write_zeros(ocf_volume_t volume,
		ocf_forward_token_t token, uint64_t addr, uint64_t bytes)
{
	ENV_BUG_ON(!volume->type->properties->ops.forward_write_zeros);

	if (!volume->opened) {
		ocf_forward_end(token, -OCF_ERR_IO);
		return;
	}

	volume->type->properties->ops.forward_write_zeros(volume, token,
			addr, bytes);
}

void ocf_volume_forward_metadata(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset)
{
	ENV_BUG_ON(!volume->type->properties->ops.forward_metadata);

	if (!volume->opened) {
		ocf_forward_end(token, -OCF_ERR_IO);
		return;
	}

	volume->type->properties->ops.forward_metadata(volume, token,
			dir, addr, bytes, offset);
}

void ocf_volume_forward_io_simple(ocf_volume_t volume,
		ocf_forward_token_t token, int dir,
		uint64_t addr, uint64_t bytes)
{

	if (!volume->type->properties->ops.forward_io_simple) {
		ocf_volume_forward_io(volume, token, dir, addr, bytes, 0);
		return;
	}

	if (!volume->opened) {
		ocf_forward_end(token, -OCF_ERR_IO);
		return;
	}

	volume->type->properties->ops.forward_io_simple(volume, token,
			dir, addr, bytes);
}

int ocf_volume_open(ocf_volume_t volume, void *volume_params)
{
	int ret;

	if (volume->opened)
		return -OCF_ERR_NOT_OPEN_EXC;

	ENV_BUG_ON(!volume->type->properties->ops.open);

	ret = volume->type->properties->ops.open(volume, volume_params);
	if (ret)
		return ret;

	env_refcnt_unfreeze(&volume->refcnt);
	volume->opened = true;

	return 0;
}

static void ocf_volume_close_end(void *ctx)
{
	env_completion *cmpl = ctx;

	env_completion_complete(cmpl);
}

void ocf_volume_close(ocf_volume_t volume)
{
	env_completion cmpl;

	ENV_BUG_ON(!volume->type->properties->ops.close);

	if (!volume->opened)
		return;

	env_completion_init(&cmpl);
	env_refcnt_freeze(&volume->refcnt);
	env_refcnt_register_zero_cb(&volume->refcnt, ocf_volume_close_end,
			&cmpl);
	env_completion_wait(&cmpl);
	env_completion_destroy(&cmpl);

	volume->type->properties->ops.close(volume);
	volume->opened = false;
}

unsigned int ocf_volume_get_max_io_size(ocf_volume_t volume)
{
	ENV_BUG_ON(!volume->type->properties->ops.get_max_io_size);

	if (!volume->opened)
		return 0;

	return volume->type->properties->ops.get_max_io_size(volume);
}

uint64_t ocf_volume_get_length(ocf_volume_t volume)
{
	ENV_BUG_ON(!volume->type->properties->ops.get_length);

	if (!volume->opened)
		return 0;

	return volume->type->properties->ops.get_length(volume);
}

int ocf_uuid_compare(const struct ocf_volume_uuid * const a,
		const struct ocf_volume_uuid * const b, int *diff)
{
	int ret, tmp_diff;

	ret = env_memcmp(a->data, a->size, b->data, b->size, &tmp_diff);
	if (ret)
		return ret;

	/*
	 * env_memcmp() compares only min(slen1, slen2) bytes. If the sizes
	 * differ, we continue comparison, assuming that any value is greater
	 * than no value, i.e. if the first uuid is shorter, the diff is -1,
	 * otherwise the diff is 1.
	 */
	if (tmp_diff || a->size == b->size)
		*diff = tmp_diff;
	else
		*diff = (a->size < b->size) ? -1 : 1;

	return 0;
}
