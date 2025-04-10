/*
 * Copyright(c) 2019-2022 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <ocf/ocf.h>
#include "volume.h"
#include "data.h"
#include "ctx.h"

#define VOL_SIZE 200*1024*1024

/*
 * In open() function we store uuid data as volume name (for debug messages)
 * and allocate 200 MiB of memory to simulate backend storage device.
 */
static int volume_open(ocf_volume_t volume, void *volume_params)
{
	const struct ocf_volume_uuid *uuid = ocf_volume_get_uuid(volume);
	struct myvolume *myvolume = ocf_volume_get_priv(volume);

	myvolume->name = ocf_uuid_to_str(uuid);
	myvolume->mem = malloc(VOL_SIZE);
	if (!myvolume->mem)
		return -ENOMEM;

	memset(myvolume->mem, 0, VOL_SIZE);

	printf("VOL OPEN: (name: %s)\n", myvolume->name);

	return 0;
}

/*
 * In close() function we just free memory allocated in open().
 */
static void volume_close(ocf_volume_t volume)
{
	struct myvolume *myvolume = ocf_volume_get_priv(volume);

	printf("VOL CLOSE: (name: %s)\n", myvolume->name);
	free(myvolume->mem);
}

void volume_forward_io(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset)
{
	struct myvolume *myvolume = ocf_volume_get_priv(volume);
	struct volume_data *data = ocf_forward_get_data(token);

	if (dir == OCF_WRITE) {
		memcpy(myvolume->mem + addr,
				data->ptr + offset, bytes);
	} else {
		memcpy(data->ptr + offset,
				myvolume->mem + addr, bytes);
	}

	printf("VOL FWD: (name: %s), IO: (dir: %s, addr: %ld, bytes: %ld)\n",
			myvolume->name, dir == OCF_READ ? "read" : "write",
			addr, bytes);

	ocf_forward_end(token, 0);
}


void volume_forward_flush(ocf_volume_t volume, ocf_forward_token_t token)
{
	ocf_forward_end(token, 0);
}

void volume_forward_discard(ocf_volume_t cvolume, ocf_forward_token_t token,
		uint64_t addr, uint64_t bytes)
{
	ocf_forward_end(token, 0);
}

/*
 * Let's set maximum io size to 128 KiB.
 */
static unsigned int volume_get_max_io_size(ocf_volume_t volume)
{
	return 128 * 1024;
}

/*
 * Return volume size.
 */
static uint64_t volume_get_length(ocf_volume_t volume)
{
	return VOL_SIZE;
}

/*
 * This structure contains volume properties. It describes volume
 * type, which can be later instantiated as backend storage for cache
 * or core.
 */
const struct ocf_volume_properties volume_properties = {
	.name = "Example volume",
	.volume_priv_size = sizeof(struct myvolume),
	.caps = {
		.atomic_writes = 0,
	},
	.ops = {
		.open = volume_open,
		.close = volume_close,
		.forward_io = volume_forward_io,
		.forward_flush = volume_forward_flush,
		.forward_discard = volume_forward_discard,
		.get_max_io_size = volume_get_max_io_size,
		.get_length = volume_get_length,
	},
};

/*
 * This function registers volume type in OCF context.
 * It should be called just after context initialization.
 */
int volume_init(ocf_ctx_t ocf_ctx)
{
	return ocf_ctx_register_volume_type(ocf_ctx, VOL_TYPE,
			&volume_properties);
}

/*
 * This function unregisters volume type in OCF context.
 * It should be called just before context cleanup.
 */
void volume_cleanup(ocf_ctx_t ocf_ctx)
{
	ocf_ctx_unregister_volume_type(ocf_ctx, VOL_TYPE);
}
