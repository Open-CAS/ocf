/*
 * Copyright(c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_priv.h"
#include "ocf_core_priv.h"
#include "ocf_io_priv.h"
#include "metadata/metadata.h"
#include "engine/cache_engine.h"
#include "utils/utils_user_part.h"
#include "ocf_request.h"
#include "ocf_composite_volume_priv.h"

#define OCF_COMPOSITE_VOLUME_MEMBERS_MAX 16

struct ocf_composite_volume {
	uint8_t members_cnt;
	struct {
		struct ocf_volume volume;
		void *volume_params;
	} member[OCF_COMPOSITE_VOLUME_MEMBERS_MAX];
	uint64_t end_addr[OCF_COMPOSITE_VOLUME_MEMBERS_MAX];
	uint64_t length;
	unsigned max_io_size;
};

struct ocf_composite_volume_io {
	struct ocf_io *member_io[OCF_COMPOSITE_VOLUME_MEMBERS_MAX];
	ctx_data_t *data;
	uint8_t begin_member;
	uint8_t end_member;
	env_atomic remaining;
	env_atomic error;
};

static void ocf_composite_volume_master_cmpl(struct ocf_io *master_io,
		int error)
{
	struct ocf_composite_volume_io *cio = ocf_io_get_priv(master_io);

	env_atomic_cmpxchg(&cio->error, 0, error);

	if (env_atomic_dec_return(&cio->remaining))
		return;

	ocf_io_end(master_io, env_atomic_read(&cio->error));
}

static void ocf_composite_volume_io_cmpl(struct ocf_io *io, int error)
{
	struct ocf_io *master_io = io->priv1;

	ocf_composite_volume_master_cmpl(master_io, error);
}

static void ocf_composite_volume_handle_io(struct ocf_io *master_io,
		void (*hndl)(struct ocf_io *io))
{
	struct ocf_composite_volume_io *cio = ocf_io_get_priv(master_io);
	int i;

	env_atomic_set(&cio->remaining,
			cio->end_member - cio->begin_member + 1);
	env_atomic_set(&cio->error, 0);

	for (i = cio->begin_member; i < cio->end_member; i++) {
		ocf_io_set_cmpl(cio->member_io[i], master_io, NULL,
				ocf_composite_volume_io_cmpl);

		cio->member_io[i]->io_class = master_io->io_class;
		cio->member_io[i]->flags = master_io->flags;

		hndl(cio->member_io[i]);
	}

	ocf_composite_volume_master_cmpl(master_io, 0);
}

static void ocf_composite_volume_submit_io(struct ocf_io *master_io)
{
	ocf_composite_volume_handle_io(master_io, ocf_volume_submit_io);
}

static void ocf_composite_volume_submit_flush(struct ocf_io *master_io)
{
	ocf_composite_volume_handle_io(master_io, ocf_volume_submit_flush);
}

static void ocf_composite_volume_submit_discard(struct ocf_io *master_io)
{
	ocf_composite_volume_handle_io(master_io, ocf_volume_submit_discard);
}

/* *** VOLUME OPS *** */

static int ocf_composite_volume_open(ocf_volume_t cvolume, void *volume_params)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	int result, i;

	composite->length = 0;
	composite->max_io_size = UINT_MAX;
	for (i = 0; i < composite->members_cnt; i++) {
		ocf_volume_t volume = &composite->member[i].volume;
		result = ocf_volume_open(volume,
				composite->member[i].volume_params);
		if (result)
			goto err;

		composite->length += ocf_volume_get_length(volume);
		composite->end_addr[i] = composite->length;
		composite->max_io_size = OCF_MIN(composite->max_io_size,
				ocf_volume_get_max_io_size(volume));
	}

	return 0;

err:
	while (i--)
		ocf_volume_close(&composite->member[i].volume);

	return result;
}

static void ocf_composite_volume_close(ocf_volume_t cvolume)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	int i;

	for (i = 0; i < composite->members_cnt; i++)
		ocf_volume_close(&composite->member[i].volume);
}

static unsigned int ocf_composite_volume_get_max_io_size(ocf_volume_t cvolume)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);

	return composite->max_io_size;
}

static uint64_t ocf_composite_volume_get_byte_length(ocf_volume_t cvolume)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);

	return composite->length;
}

static void ocf_composite_volume_on_deinit(ocf_volume_t cvolume)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	int i;

	for (i = 0; i < composite->members_cnt; i++)
		ocf_volume_deinit(&composite->member[i].volume);
}

/* *** IO OPS *** */

static int ocf_composite_io_set_data(struct ocf_io *io,
		ctx_data_t *data, uint32_t offset)
{
	ocf_volume_t cvolume = ocf_io_get_volume(io);
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	struct ocf_composite_volume_io *cio = ocf_io_get_priv(io);
	uint64_t member_volume_start, member_data_offset;
	int i, ret = 0;

	cio->data = data;

	for (i = cio->begin_member; i < cio->end_member; i++) {
		/* Each member IO will have the same data set, but with
		 * different offset. First member will use bare offset set from
		 * caller, each subsequent member IO has to skip over parts
		 * "belonging" to previous members. */

		if (i == cio->begin_member) {
			member_data_offset = offset;
		} else {
			member_volume_start = composite->end_addr[i - 1];
			member_data_offset = member_volume_start - io->addr;
			member_data_offset += offset;
		}

		ret = ocf_io_set_data(cio->member_io[i], data,
				member_data_offset);
		if (ret)
			break;
	}

	return ret;
}

static ctx_data_t *ocf_composite_io_get_data(struct ocf_io *io)
{
	struct ocf_composite_volume_io *cio = ocf_io_get_priv(io);

	return cio->data;
}

const struct ocf_volume_properties ocf_composite_volume_properties = {
	.name = "OCF Composite",
	.io_priv_size = sizeof(struct ocf_composite_volume_io),
	.volume_priv_size = sizeof(struct ocf_composite_volume),
	.caps = {
		.atomic_writes = 0,
	},
	.ops = {
		.submit_io = ocf_composite_volume_submit_io,
		.submit_flush = ocf_composite_volume_submit_flush,
		.submit_discard = ocf_composite_volume_submit_discard,
		.submit_metadata = NULL,

		.open = ocf_composite_volume_open,
		.close = ocf_composite_volume_close,
		.get_max_io_size = ocf_composite_volume_get_max_io_size,
		.get_length = ocf_composite_volume_get_byte_length,

		.on_deinit = ocf_composite_volume_on_deinit,
	},
	.io_ops = {
		.set_data = ocf_composite_io_set_data,
		.get_data = ocf_composite_io_get_data,
	},
	.deinit = NULL,
};

static int ocf_composite_io_allocator_init(ocf_io_allocator_t allocator,
		uint32_t priv_size, const char *name)
{
	return ocf_io_allocator_default_init(allocator, priv_size, name);
}

static void ocf_composite_io_allocator_deinit(ocf_io_allocator_t allocator)
{
	ocf_io_allocator_default_deinit(allocator);
}

static void *ocf_composite_io_allocator_new(ocf_io_allocator_t allocator,
		ocf_volume_t cvolume, ocf_queue_t queue,
		uint64_t addr, uint32_t bytes, uint32_t dir)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	struct ocf_composite_volume_io *cio;
	struct ocf_io_internal *ioi;
	uint64_t member_addr, member_bytes, cur_addr, cur_bytes;
	int i;

	ioi = ocf_io_allocator_default_new(allocator, cvolume, queue,
			addr, bytes, dir);
	if (!ioi)
		return NULL;

	cio = ocf_io_get_priv(&ioi->io);

	if (bytes == 0) {
		/* Flush io - allocate io for each volume */
		for (i = 0; i < composite->members_cnt; i++) {
			cio->member_io[i] = ocf_io_new(&composite->member[i].volume,
					queue, 0, 0, dir, 0, 0);
			if (!cio->member_io[i])
				goto err;
		}
		cio->begin_member = 0;
		cio->end_member = composite->members_cnt;

		return ioi;
	}

	for (i = 0; i < composite->members_cnt; i++) {
		if (addr < composite->end_addr[i]) {
			cio->begin_member = i;
			break;
		}
	}

	cur_addr = addr;
	cur_bytes = bytes;

	for (; i < composite->members_cnt; i++) {
		member_addr = cur_addr - (i > 0 ? composite->end_addr[i-1] : 0);
		member_bytes =
			OCF_MIN(cur_addr + cur_bytes, composite->end_addr[i])
			- cur_addr;

		cio->member_io[i] = ocf_io_new(&composite->member[i].volume, queue,
				member_addr, member_bytes, dir, 0, 0);
		if (!cio->member_io[i])
			goto err;

		cur_addr += member_bytes;
		cur_bytes -= member_bytes;

		if (!cur_bytes) {
			cio->end_member = i + 1;
			break;
		}
	}

	ENV_BUG_ON(cur_bytes != 0);

	return ioi;

err:
	for (i = 0; i < composite->members_cnt; i++) {
		if (cio->member_io[i])
			ocf_io_put(cio->member_io[i]);
	}

	ocf_io_allocator_default_del(allocator, ioi);

	return NULL;
}

static void ocf_composite_io_allocator_del(ocf_io_allocator_t allocator, void *obj)
{
	struct ocf_io_internal *ioi = obj;
	struct ocf_composite_volume_io *cio = ocf_io_get_priv(&ioi->io);
	int i;

	for (i = cio->begin_member; i < cio->end_member; i++) {
		if (cio->member_io[i])
			ocf_io_put(cio->member_io[i]);
	}

	ocf_io_allocator_default_del(allocator, ioi);
}

const struct ocf_io_allocator_type ocf_composite_io_allocator_type = {
	.ops = {
		.allocator_init = ocf_composite_io_allocator_init,
		.allocator_deinit = ocf_composite_io_allocator_deinit,
		.allocator_new = ocf_composite_io_allocator_new,
		.allocator_del = ocf_composite_io_allocator_del,
	},
};

const struct ocf_volume_extended ocf_composite_volume_extended = {
	.allocator_type = &ocf_composite_io_allocator_type,
};

int ocf_composite_volume_type_init(ocf_ctx_t ctx)
{
	return ocf_ctx_register_volume_type_internal(ctx,
			OCF_VOLUME_TYPE_COMPOSITE,
			&ocf_composite_volume_properties,
			&ocf_composite_volume_extended);
}

int ocf_composite_volume_create(ocf_composite_volume_t *volume, ocf_ctx_t ctx)
{
	ocf_volume_type_t type;

	type = ocf_ctx_get_volume_type_internal(ctx, OCF_VOLUME_TYPE_COMPOSITE);
	if (!type)
		return -OCF_ERR_INVAL;

	return ocf_volume_create(volume, type, NULL);
}

void ocf_composite_volume_destroy(ocf_composite_volume_t cvolume)
{
	ocf_volume_destroy(cvolume);
}

int ocf_composite_volume_add(ocf_composite_volume_t cvolume,
		ocf_volume_type_t type, struct ocf_volume_uuid *uuid,
		void *volume_params)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	ocf_volume_t volume;
	int result;

	if (composite->members_cnt >= OCF_COMPOSITE_VOLUME_MEMBERS_MAX)
		return -OCF_ERR_INVAL;

	volume = &composite->member[composite->members_cnt].volume;
	result = ocf_volume_init(volume, type, uuid, true);
	if (result)
		return result;

	composite->member[composite->members_cnt].volume_params = volume_params;
	composite->members_cnt++;

	return 0;
}
