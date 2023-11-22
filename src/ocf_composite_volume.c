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
	/* 'members_cnt' describes how many members were added at the
	 * composite initialization. Even if a member is detached,
	 * 'member_cnt' shall not be decremented.
	 */
	uint8_t members_cnt;
	struct {
		/* A member is 'detached' only if it was once added but has
		 * been detached. For members that were never added, this
		 * flag is irrelevant
		 */
		bool detached;
		struct ocf_volume volume;
		void *volume_params;
	} member[OCF_COMPOSITE_VOLUME_MEMBERS_MAX];
	uint64_t end_addr[OCF_COMPOSITE_VOLUME_MEMBERS_MAX];
	uint64_t length;
	unsigned max_io_size;
};

#define for_each_composite_member(_composite, _id) \
	for ((_id) = 0; (_id) < (_composite)->members_cnt; (_id)++)

#define for_each_composite_member_attached(_composite, _id) \
	for_each_composite_member((_composite), (_id)) \
		if ((_composite)->member[(_id)].detached == false)

#define for_each_composite_member_detached(_composite, _id) \
	for_each_composite_member((_composite), (_id)) \
		if ((_composite)->member[(_id)].detached == true)

#define for_each_composite_member_opened(_composite, _id) \
	for_each_composite_member_attached((_composite), (_id)) \
		if ((_composite)->member[(_id)].volume.opened == true)

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

	for_each_composite_member_opened(composite, i) {
		ocf_forward_flush(&composite->member[i].volume, token);
	}

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
	int result, i, j;

	for_each_composite_member_attached(composite, i) {
		ocf_volume_t volume = &composite->member[i].volume;
		result = ocf_volume_open(volume,
				composite->member[i].volume_params);
		if (result)
			goto err;
	}

	return 0;

err:
	for_each_composite_member_attached(composite, j) {
		if (j >= i)
			break;
		ocf_volume_close(&composite->member[j].volume);
	}

	return result;
}

static void ocf_composite_volume_close(ocf_volume_t cvolume)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	int i;

	for_each_composite_member_opened(composite, i)
		ocf_volume_close(&composite->member[i].volume);
}

#define get_subvolume_length(_composite, _id) \
	(_id == 0 ? _composite->end_addr[_id] : \
	_composite->end_addr[_id] - _composite->end_addr[_id - 1])

static int composite_volume_attach_member(ocf_volume_t cvolume,
		ocf_uuid_t uuid, uint8_t tgt_id, ocf_volume_type_t vol_type,
		void *vol_params)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	ocf_ctx_t ctx = cvolume->type->owner;
	struct ocf_volume new_vol = {};
	uint64_t new_vol_size, tgt_vol_size;
	unsigned new_vol_max_io_size;
	int ret;

	if (tgt_id >= OCF_COMPOSITE_VOLUME_MEMBERS_MAX) {
		ocf_log(ctx, log_err, "Failed to attach subvolume to "
				"the composite volume. Invalid subvolume "
				"target id\n");
		return -OCF_ERR_COMPOSITE_INVALID_ID;
	}

	if (tgt_id >= composite->members_cnt) {
		ocf_log(ctx, log_err, "Failed to attach subvolume to "
				"the composite volume. Can't attach to "
				"uninitialized member\n");
		return -OCF_ERR_COMPOSITE_UNINITIALISED_VOLUME;
	}

	if (!composite->member[tgt_id].detached) {
		ocf_log(ctx, log_err, "Failed to attach subvolume to "
				"the composite volume. The target member is "
				"already attached\n");
		return -OCF_ERR_COMPOSITE_ATTACHED;
	}

	ret = ocf_volume_init(&new_vol, vol_type, uuid, true);
	if (ret)
		return ret;

	ret = ocf_volume_open(&new_vol, vol_params);
	if (ret) {
		ocf_volume_deinit(&new_vol);
		return ret;
	}

	new_vol_size = ocf_volume_get_length(&new_vol);

	new_vol_max_io_size = ocf_volume_get_max_io_size(&new_vol);

	ocf_volume_close(&new_vol);

	tgt_vol_size = get_subvolume_length(composite, tgt_id);

	if (new_vol_size != tgt_vol_size) {
		ocf_log(ctx, log_err, "Failed to attach subvolume to "
				"the composite volume. The new subvolume must "
				"be of size %"ENV_PRIu64" but "
				"is %"ENV_PRIu64"\n", tgt_vol_size,
				new_vol_size);
		ocf_volume_deinit(&new_vol);
		return -OCF_ERR_COMPOSITE_INVALID_SIZE;
	}

	if (composite->max_io_size > new_vol_max_io_size) {
		ocf_log(ctx, log_err, "Failed to attach subvolume to the "
				"composite volume. The max io size can't be "
				"smaller than composite's max io size\n");
		ocf_volume_deinit(&new_vol);
		return -OCF_ERR_INVAL;
	}

	ocf_volume_move(&composite->member[tgt_id].volume, &new_vol);
	ocf_volume_deinit(&new_vol);

	if (cvolume->opened) {
		ret = ocf_volume_open(&composite->member[tgt_id].volume,
				vol_params);
		if (ret) {
			ocf_volume_deinit(&composite->member[tgt_id].volume);
			return ret;
		}
	}

	composite->member[tgt_id].detached = false;
	composite->member[tgt_id].volume_params = vol_params;

	return 0;
}

static int composite_volume_detach_member(ocf_volume_t cvolume,
		uint8_t subvolume_id)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	ocf_ctx_t ctx = cvolume->type->owner;

	if (subvolume_id >= OCF_COMPOSITE_VOLUME_MEMBERS_MAX) {
		ocf_log(ctx, log_err, "Failed to detach subvolume from "
				"the composite volume. Invalid subvolume "
				"target id\n");
		return -OCF_ERR_COMPOSITE_INVALID_ID;
	}

	if (subvolume_id >= composite->members_cnt) {
		ocf_log(ctx, log_err, "Failed to detach subvolume from "
				"the composite volume. Can't detach "
				"uninitialized member\n");
		return -OCF_ERR_COMPOSITE_UNINITIALISED_VOLUME;
	}

	if (composite->member[subvolume_id].detached) {
		ocf_log(ctx, log_err, "Failed to detach subvolume from "
				"the composite volume. The target member is "
				"already detached\n");
		return -OCF_ERR_COMPOSITE_DETACHED;
	}

	ocf_volume_close(&composite->member[subvolume_id].volume);

	composite->member[subvolume_id].detached = true;
	composite->member[subvolume_id].volume_params = NULL;

	return 0;
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

static int ocf_composite_volume_on_init(ocf_volume_t cvolume)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);

	composite->length = 0;
	composite->max_io_size = UINT_MAX;

	return 0;
}

static void ocf_composite_volume_on_deinit(ocf_volume_t cvolume)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	int i;

	for (i = 0; i < composite->members_cnt; i++)
		ocf_volume_deinit(&composite->member[i].volume);
}

static int composite_volume_add(ocf_volume_t cvolume, ocf_volume_type_t type,
		struct ocf_volume_uuid *uuid, void *volume_params)
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

	result = ocf_volume_open(volume, volume_params);
	if (result) {
		ocf_volume_deinit(volume);
		return result;
	}

	composite->length += ocf_volume_get_length(volume);
	composite->end_addr[composite->members_cnt] = composite->length;
	composite->max_io_size = OCF_MIN(composite->max_io_size,
			ocf_volume_get_max_io_size(volume));

	ocf_volume_close(volume);

	composite->member[composite->members_cnt].volume_params = volume_params;
	composite->member[composite->members_cnt].detached = false;
	composite->members_cnt++;

	return 0;
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

		.on_init = ocf_composite_volume_on_init,
		.composite_volume_attach_member =
			composite_volume_attach_member,
		.composite_volume_detach_member =
			composite_volume_detach_member,
		.on_deinit = ocf_composite_volume_on_deinit,

		.composite_volume_add = composite_volume_add,
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

int ocf_composite_volume_member_visit(ocf_composite_volume_t cvolume,
		ocf_composite_volume_member_visitor_t visitor, void *priv,
		ocf_composite_member_state_t svol_status)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	int i;
	int res;
	ocf_composite_member_state_t s;

	if (svol_status != ocf_composite_member_state_attached &&
			svol_status != ocf_composite_member_state_opened &&
			svol_status != ocf_composite_member_state_detached &&
			svol_status != ocf_composite_member_state_any) {
		return -OCF_ERR_INVAL;
	}

	for_each_composite_member(composite, i) {
		if (composite->member[i].detached)
			s = ocf_composite_member_state_detached;
		else if (composite->member[i].volume.opened)
			s = ocf_composite_member_state_opened;
		else
			s = ocf_composite_member_state_attached;

		if (!(s & svol_status))
			continue;

		res = visitor(&composite->member[i].volume, priv, s);
		if (res != 0)
			return res;
	}

	return 0;
}

ocf_volume_t ocf_composite_volume_get_subvolume_by_index(
		ocf_composite_volume_t cvolume, int index)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);

	if (index >= 0 && index < composite->members_cnt)
		return &composite->member[index].volume;
	else
		return NULL;
}

int ocf_composite_volume_get_subvolume_addr_range(
		ocf_composite_volume_t cvolume, uint8_t subvolume_id,
		uint64_t *begin_addr, uint64_t *end_addr)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);

	if (subvolume_id >= composite->members_cnt)
		return -OCF_ERR_INVAL;

	*begin_addr = subvolume_id > 0 ?
			composite->end_addr[subvolume_id - 1] : 0;
	*end_addr = composite->end_addr[subvolume_id];

	return 0;
}

int ocf_composite_volume_set_uuid(ocf_composite_volume_t cvolume,
		struct ocf_volume_uuid *uuid)
{
	return ocf_volume_set_uuid(cvolume, uuid, true);
}

int ocf_composite_volume_get_id_from_uuid(ocf_composite_volume_t cvolume,
		ocf_uuid_t target_uuid)
{
	struct ocf_composite_volume *composite = ocf_volume_get_priv(cvolume);
	const struct ocf_volume_uuid *subvol_uuid;
	int i;

	for_each_composite_member_attached(composite, i) {
		subvol_uuid = ocf_volume_get_uuid(&composite->member[i].volume);
		if (env_strncmp(subvol_uuid->data, subvol_uuid->size,
				target_uuid->data, target_uuid->size) == 0) {
			return i;
		}
	}

	return -OCF_ERR_COMPOSITE_VOLUME_MEMBER_NOT_EXIST;
}
