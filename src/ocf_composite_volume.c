/*
 * Copyright(c) 2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
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

static void ocf_composite_forward_io(ocf_volume_t cvolume,
		ocf_forward_token_t token, int dir, uint64_t addr,
		uint64_t bytes, uint64_t offset)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	uint64_t member_bytes, caddr;
	int i;

	ENV_BUG_ON(addr >= composite->length);
	ENV_BUG_ON(addr + bytes > composite->length);

	caddr = addr;

	for (i = 0; i < composite->members_cnt; i++) {
		if (addr >= composite->end_addr[i])
			continue;

		if (unlikely(!composite->member[i].volume.opened)) {
			ocf_forward_end(token, -OCF_ERR_INVAL);
			return;
		}

		addr = addr - (i > 0 ? composite->end_addr[i-1] : 0);
		break;
	}

	for (; i < composite->members_cnt && bytes; i++) {
		if (unlikely(!composite->member[i].volume.opened)) {
			ocf_forward_end(token, -OCF_ERR_INVAL);
			return;
		}

		member_bytes = OCF_MIN(bytes, composite->end_addr[i] - caddr);

		ocf_forward_io(&composite->member[i].volume, token, dir, addr,
				member_bytes, offset);

		addr = 0;
		caddr = composite->end_addr[i];
		bytes -= member_bytes;
		offset += member_bytes;
	}

	/* Put io forward counter to account for the original forward */
	ocf_forward_end(token, 0);
}

static void ocf_composite_forward_flush(ocf_volume_t cvolume,
		ocf_forward_token_t token)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	int i;

	for (i = 0; i < composite->members_cnt; i++)
		ocf_forward_flush(&composite->member[i].volume, token);

	/* Put io forward counter to account for the original forward */
	ocf_forward_end(token, 0);
}

static void ocf_composite_forward_discard(ocf_volume_t cvolume,
		ocf_forward_token_t token, uint64_t addr, uint64_t bytes)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	uint64_t member_bytes, caddr;
	int i;

	caddr = addr;

	ENV_BUG_ON(addr >= composite->length);
	ENV_BUG_ON(addr + bytes > composite->length);

	for (i = 0; i < composite->members_cnt; i++) {
		if (addr >= composite->end_addr[i])
			continue;

		if (unlikely(!composite->member[i].volume.opened)) {
			ocf_forward_end(token, -OCF_ERR_INVAL);
			return;
		}

		addr = addr - (i > 0 ? composite->end_addr[i-1] : 0);
		break;
	}

	for (; i < composite->members_cnt && bytes; i++) {
		if (unlikely(!composite->member[i].volume.opened)) {
			ocf_forward_end(token, -OCF_ERR_INVAL);
			return;
		}

		member_bytes = OCF_MIN(bytes, composite->end_addr[i] - caddr);

		ocf_forward_discard(&composite->member[i].volume, token, addr,
				member_bytes);

		addr = 0;
		caddr = composite->end_addr[i];
		bytes -= member_bytes;
	}

	/* Put io forward counter to account for the original forward */
	ocf_forward_end(token, 0);
}

static void ocf_composite_forward_write_zeros(ocf_volume_t cvolume,
		ocf_forward_token_t token, uint64_t addr, uint64_t bytes)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	uint64_t member_bytes, caddr;
	int i;

	caddr = addr;

	ENV_BUG_ON(addr >= composite->length);
	ENV_BUG_ON(addr + bytes > composite->length);

	for (i = 0; i < composite->members_cnt; i++) {
		if (addr >= composite->end_addr[i])
			continue;

		if (unlikely(!composite->member[i].volume.opened)) {
			ocf_forward_end(token, -OCF_ERR_INVAL);
			return;
		}

		addr = addr - (i > 0 ? composite->end_addr[i-1] : 0);
		break;
	}

	for (; i < composite->members_cnt && bytes; i++) {
		if (unlikely(!composite->member[i].volume.opened)) {
			ocf_forward_end(token, -OCF_ERR_INVAL);
			return;
		}

		member_bytes = OCF_MIN(bytes, composite->end_addr[i] - caddr);

		ocf_forward_write_zeros(&composite->member[i].volume, token,
				addr, member_bytes);

		addr = 0;
		caddr = composite->end_addr[i];
		bytes -= member_bytes;
	}

	/* Put io forward counter to account for the original forward */
	ocf_forward_end(token, 0);
}

static void ocf_composite_forward_metadata(ocf_volume_t cvolume,
		ocf_forward_token_t token, int dir, uint64_t addr,
		uint64_t bytes, uint64_t offset)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	uint64_t member_bytes, caddr;
	int i;

	ENV_BUG_ON(addr >= composite->length);
	ENV_BUG_ON(addr + bytes > composite->length);

	caddr = addr;

	for (i = 0; i < composite->members_cnt; i++) {
		if (addr >= composite->end_addr[i])
			continue;

		if (unlikely(!composite->member[i].volume.opened)) {
			ocf_forward_end(token, -OCF_ERR_INVAL);
			return;
		}

		addr = addr - (i > 0 ? composite->end_addr[i-1] : 0);
		break;
	}

	for (; i < composite->members_cnt && bytes; i++) {
		if (unlikely(!composite->member[i].volume.opened)) {
			ocf_forward_end(token, -OCF_ERR_INVAL);
			return;
		}

		member_bytes = OCF_MIN(bytes, composite->end_addr[i] - caddr);

		ocf_forward_metadata(&composite->member[i].volume, token, dir,
				addr, member_bytes, offset);

		addr = 0;
		caddr = composite->end_addr[i];
		bytes -= member_bytes;
		offset += member_bytes;
	}

	/* Put io forward counter to account for the original forward */
	ocf_forward_end(token, 0);
}

static void ocf_composite_forward_io_simple(ocf_volume_t cvolume,
		ocf_forward_token_t token, int dir,
		uint64_t addr, uint64_t bytes)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	uint64_t caddr;
	int i;

	ENV_BUG_ON(addr >= composite->length);
	ENV_BUG_ON(addr + bytes > composite->length);

	caddr = addr;

	for (i = 0; i < composite->members_cnt; i++) {
		if (addr >= composite->end_addr[i])
			continue;

		if (unlikely(!composite->member[i].volume.opened)) {
			ocf_forward_end(token, -OCF_ERR_IO);
			return;
		}

		addr = addr - (i > 0 ? composite->end_addr[i-1] : 0);
		break;
	}

	if (caddr + bytes > composite->end_addr[i]) {
		ocf_forward_end(token, -OCF_ERR_IO);
		return;
	}

	ocf_forward_io_simple(&composite->member[i].volume, token,
			dir, addr, bytes);

	/* Put io forward counter to account for the original forward */
	ocf_forward_end(token, 0);
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

const struct ocf_volume_properties ocf_composite_volume_properties = {
	.name = "OCF Composite",
	.volume_priv_size = sizeof(struct ocf_composite_volume),
	.caps = {
		.atomic_writes = 0,
		.composite_volume = 1,
	},
	.ops = {
		.forward_io = ocf_composite_forward_io,
		.forward_flush = ocf_composite_forward_flush,
		.forward_discard = ocf_composite_forward_discard,
		.forward_write_zeros = ocf_composite_forward_write_zeros,
		.forward_metadata = ocf_composite_forward_metadata,
		.forward_io_simple = ocf_composite_forward_io_simple,

		.open = ocf_composite_volume_open,
		.close = ocf_composite_volume_close,
		.get_max_io_size = ocf_composite_volume_get_max_io_size,
		.get_length = ocf_composite_volume_get_byte_length,

		.on_deinit = ocf_composite_volume_on_deinit,
	},
	.deinit = NULL,
};

int ocf_composite_volume_type_init(ocf_ctx_t ctx)
{
	return ocf_ctx_register_volume_type_internal(ctx,
			OCF_VOLUME_TYPE_COMPOSITE,
			&ocf_composite_volume_properties, NULL);
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

int ocf_composite_volume_member_visit(ocf_composite_volume_t cvolume,
		ocf_composite_volume_member_visitor_t visitor, void *priv)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	int i;
	int res;

	for (i = 0 ; i < composite->members_cnt; i++) {
		res = visitor(&composite->member[i].volume, priv);
		if (res != 0)
			return res;
	}

	return 0;
}
