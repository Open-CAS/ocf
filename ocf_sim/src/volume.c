/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "volume.h"

#include <ocf/ocf.h>
#include <ocf_env.h>
#include <ocf/ocf_blktrace.h>
#include <ocf/ocf_prefetch_common.h>
#include "ocf/ocf_volume_priv.h"

#include "ctx.h"
#include "data.h"
#include "scheduler.h"
#include "vol_sim.h"

#define VOL_SIZE 4096		// minimum size for cache volume detection
#define BUFSIZE 80

typedef struct {
	uint8_t *mem;
	const char *name;
} myvolume_t;

struct myvolume_io {
	struct volume_data* data;
	uint32_t offset;
};

/*
 * Return volume size.
 */
static uint64_t volume_get_length(ocf_volume_t volume)
{
	myvolume_t *myvolume = ocf_volume_get_priv(volume);

	if (!strncmp(myvolume->name, "cache", 5))
		return (myvolume->name[5] == '0') ? top_msla_vol_sz : cache_vol_sz;
	return backend_vol_sz;
}

/*
 * In open() function we store uuid data as volume name (for debug messages)
 */
static int volume_open(ocf_volume_t volume, void* vol_params)
{
	const struct ocf_volume_uuid* uuid = ocf_volume_get_uuid(volume);
	myvolume_t *myvolume = ocf_volume_get_priv(volume);

	myvolume->name = ocf_uuid_to_str(uuid);
	myvolume->mem = calloc(1, VOL_SIZE);

	ocf_log(3, "VOL OPEN: %s size %ld (%ld GB = %ld GiB)\n", myvolume->name,
		volume_get_length(volume), volume_get_length(volume) / (1000 * 1000 * 1000), volume_get_length(volume) >> 30);

	return 0;
}

/*
 * In close() function we just free memory allocated in open().
 */
static void volume_close(ocf_volume_t volume)
{
	myvolume_t *myvolume = ocf_volume_get_priv(volume);

	ocf_log(3, "VOL CLOSE: %s)\n", myvolume->name);
	free(myvolume->mem);
}

/*
 * In submit_io() function we simulate read or write to backend storage device
 * by doing memcpy() to or from previously allocated memory buffer.
 */
void volume_complete_io(ocf_io_t *ocf_io)
{
	ocf_forward_token_t token = (ocf_forward_token_t)ocf_io->priv;

	ocf_fwd_end(ocf_io->volume, ocf_io->addr, token, 0);
	env_free(ocf_io);
}

// This function is needed to copy the IO data during _ocf_mngt_test_volume_pipeline_properties
static void submit_io_during_init(ocf_io_t *ocf_io, uint32_t offset)
{
	myvolume_t *myvolume = ocf_volume_get_priv(ocf_io->volume);
	struct volume_data *data = ocf_io->data;

	if (ocf_io->addr + ocf_io->bytes <= VOL_SIZE && data->ptr) {
		if (ocf_io->dir == OCF_WRITE) {
			memcpy(myvolume->mem + ocf_io->addr, data->ptr + offset, ocf_io->bytes);
		}
		else {
			memcpy(data->ptr + offset, myvolume->mem + ocf_io->addr, ocf_io->bytes);
		}
	}
	OCF_BLKTRACE_SUBMIT_IO(ocf_io);
	ocf_log_timestamp(3, "VOL IO: %s %s %ld + %d%s\n",
			myvolume->name, ocf_io->dir == OCF_READ ? "read" : "write",
			ocf_io->addr >> ENV_SECTOR_SHIFT, ocf_io->bytes >> ENV_SECTOR_SHIFT, ocf_io->pa_id ? " - prefetch" : "");
	volume_complete_io(ocf_io);
}

static void volume_submit_io(ocf_io_t *ocf_io, uint32_t offset)
{
	if (!scheduler_is_active()) {
		submit_io_during_init(ocf_io, offset);
		return;
	}
	if (!OCF_BLKTRACE_IS_VALID(ocf_io->blktrace)) {
		ocf_log_timestamp(0, "%s (%d): Illegal blktrace signature (%ld)\n", __func__, __LINE__, ocf_io->blktrace->signature);
		volume_complete_io(ocf_io);
		return;
	}

	OCF_BLKTRACE_SUBMIT_IO(ocf_io);
	volsim_submit_io(ocf_io);
}

static void volume_forward_io(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset)
{
	struct ocf_request *req = ocf_req_forward_token_to_req(token);
	ocf_io_t *ocf_io = env_zalloc(sizeof(ocf_io_t), ENV_MEM_NORMAL);

	if (unlikely(ocf_io == NULL)) {
		ocf_log_timestamp(0, "%s (%d): Failed to allocate ocf_io\n", __func__, __LINE__);
		ocf_fwd_end(volume, addr, token, -ENOMEM);
		return;
	}

	ocf_io->volume = volume;
	ocf_io->data = ocf_forward_get_data(token);
	ocf_io->priv = (void *)token;
	ocf_io->addr = addr;
	ocf_io->bytes = bytes;
	ocf_io->dir = dir;
	ocf_io->pa_id = req->io.pa_id;
	ocf_io->blktrace = &req->io.ocf_io_blktrace;

	volume_submit_io(ocf_io, req->offset);
}

static void volume_forward_flush(ocf_volume_t volume, ocf_forward_token_t token)
{
	ocf_fwd_end(volume, -1, token, 0);
}

static void volume_forward_discard(ocf_volume_t volume,
		ocf_forward_token_t token, uint64_t addr, uint64_t bytes)
{
	ocf_fwd_end(volume, addr, token, 0);
}

/*
 * Let's set maximum io size to 128 KiB.
 */
static unsigned int volume_get_max_io_size(ocf_volume_t volume)
{
	return 128 * 1024;
}

/*
 * These structures contains volume properties.
 * It describes volume type
 */
const struct ocf_volume_properties volume_properties = {
	.name = "ocf_sim volume",
	.volume_priv_size = sizeof(myvolume_t),
	.caps = {
		.atomic_writes = 0,
		.composite_volume = 0,
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
	return ocf_ctx_register_volume_type(ocf_ctx, VOLUME_TYPE,
		&volume_properties);
}

/*
 * This function unregisters volume type in OCF context.
 * It should be called just before context cleanup.
 */
void volume_cleanup(ocf_ctx_t ocf_ctx)
{
	ocf_ctx_unregister_volume_type(ocf_ctx, VOLUME_TYPE);
}
