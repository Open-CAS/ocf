/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifdef OCF_BLKTRACE
#include "ocf/ocf_blktrace.h"

#include "ocf_env.h"
#include "ocf/ocf_cache.h"
#include "ocf/ocf_volume.h"
#include "../ocf_request.h"
#include "ocf/ocf_prefetch_common.h"

/* For default function only return the timestamp */
static void blktrace_cb_func(const ocf_blktrace_const_data_t *const_data,
			ocf_io_t *ocf_io,
			ocf_blktrace_orig_on_remap_t *orig_on_remap,
			ocf_blktrace_ts_t *ts) // [OT] - Current timestamp
{
	env_ticks_to_nsecs(env_get_tick_count());
}

/* Register database */
static const ocf_blktrace_register_t s_register_init = {
	.blktrace_ext_func = blktrace_cb_func,
	.volsim_create = NULL,
	.volsim_destroy = NULL,
	};

static ocf_blktrace_register_t s_register = s_register_init;

/* Let the user (casadm/spdk/ocf_sim) de-register with its own functions */
void ocf_blktrace_de_register(void)
{
	s_register = s_register_init;
}

static inline void blktrace_ext_func(const ocf_blktrace_const_data_t *const_data,
			ocf_io_t *ocf_io,
			ocf_blktrace_orig_on_remap_t *orig_on_remap,
			struct ocf_request *req)
{
	ocf_blktrace_ts_t ts;

	if (req != NULL) {
		ocf_io->bytes = req->bytes;
		ocf_io->pa_id = req->io.pa_id;;
		ocf_io->blktrace = &req->io.ocf_io_blktrace;
		ocf_io->priv = (void *)ocf_req_to_core_forward_token(req);
	}

	s_register.blktrace_ext_func(const_data, ocf_io, orig_on_remap, &ts);
	ocf_io->blktrace->last_ts = ts;
}

/*
 * Build a new blktrace primitve for the new IO.
 * The orig_req is the request that triggered the new IO.
 */
void ocf_blktrace_new(const ocf_blktrace_const_data_t *const_data,
		      struct ocf_request *req, struct ocf_request *trigger_req)
{
	ocf_blktrace_orig_on_remap_t orig_on_remap;
	ocf_blktrace_orig_on_remap_t *orig_on_remap_ptr;
	ocf_io_t ocf_io = {
		.volume = (req->core != NULL)
				? ocf_io_get_volume(req)
				: ocf_cache_get_volume(req->cache),
		.addr = req->addr,
		.dir = req->rw,
	};
	ocf_blktrace_io_t *blktrace = ocf_blktrace_get(req);

	if (trigger_req) {	/* Called from the OCF */
		ocf_blktrace_io_t *trig_blktrace = ocf_blktrace_get(trigger_req);

		blktrace->last_ts = trig_blktrace->last_ts;	/* For the blkparse delta time */
		blktrace->priv = trig_blktrace->priv;
		orig_on_remap.volume = ocf_io_get_volume(req);
		orig_on_remap.addr = trigger_req->addr;
		orig_on_remap_ptr = &orig_on_remap;
	} else {
		orig_on_remap_ptr = NULL;
	}

	if (ocf_io.volume == NULL) {
		req->io.volume = ocf_io.volume = req->core
					? ocf_core_get_front_volume(req->core)
					: ocf_cache_get_volume(req->cache);
	}
	OCF_BLKTRACE_SET_SIGNATURE(blktrace);
	env_memset(&blktrace->q_ts, sizeof(blktrace->q_ts), 0);
	blktrace_ext_func(const_data, &ocf_io, orig_on_remap_ptr, req);
	blktrace->q_ts = blktrace->last_ts;
}

/*
 * Let the user (casadm/spdk/ocf_sim) register with its own functions
 */
void ocf_blktrace_register(const ocf_blktrace_register_t *reg)
{
	if (reg) {
		if (reg->blktrace_ext_func) {
			s_register.blktrace_ext_func = reg->blktrace_ext_func;
		}
		if (reg->volsim_create) {
			s_register.volsim_create = reg->volsim_create;
		}
		if (reg->volsim_destroy) {
			s_register.volsim_destroy = reg->volsim_destroy;
		}
	}
}

/*
 * Remap Composite
 */
void ocf_blktrace_remap_composite(const ocf_blktrace_const_data_t *const_data,
				ocf_volume_t volume, uint64_t addr, uint64_t caddr,
				ocf_forward_token_t token, uint8_t dir)
{
	struct ocf_request *req = ocf_req_forward_token_to_req(token);
	ocf_blktrace_orig_on_remap_t orig_on_remap = {
		.volume = ocf_cache_get_volume(req->cache),
		.addr = caddr
	};
	ocf_io_t ocf_io = {
		.volume = volume,
		.addr = addr,
		.dir = dir,
	};

	blktrace_ext_func(const_data, &ocf_io, &orig_on_remap, req);
}

/*
 * Remap FE to BE.
 */
void ocf_blktrace_remap_to_be(const ocf_blktrace_const_data_t *const_data,
		      		     struct ocf_request *req)
{
	ocf_volume_t core_volume = ocf_core_get_volume(req->core);
	ocf_blktrace_orig_on_remap_t orig_on_remap = {
		.volume = ocf_io_get_volume(req),
		.addr = req->addr
	};
	ocf_io_t ocf_io = {
		.volume = core_volume,
		.addr = req->addr,
		.dir = req->rw,
	};

	blktrace_ext_func(const_data, &ocf_io, &orig_on_remap, req);
}

/*
 * Remap to cache.
 */
void ocf_blktrace_remap_to_cache(const ocf_blktrace_const_data_t *const_data,
			struct ocf_request *req, uint64_t addr, uint8_t dir)
{
	ocf_blktrace_orig_on_remap_t orig_on_remap = {
		.volume = (req->core == NULL)
				? ocf_cache_get_volume(req->cache)
				: ocf_io_get_volume(req),
		.addr = req->addr
	};
	ocf_io_t ocf_io = {
		.volume = ocf_cache_get_volume(req->cache),
		.addr = addr,
		.dir = dir,
	};

	blktrace_ext_func(const_data, &ocf_io, &orig_on_remap, req);
}

/* Report and update ts */
void ocf_blktrace_update(const ocf_blktrace_const_data_t *const_data, ocf_io_t *ocf_io)
{
	blktrace_ext_func(const_data, ocf_io, NULL, NULL);
}

void ocf_blktrace_update_req(const ocf_blktrace_const_data_t *const_data,
				struct ocf_request *req)
{
	ocf_io_t ocf_io = {
		.volume = ocf_io_get_volume(req),
		.addr = req->addr,
		.dir = req->rw,
	};

	blktrace_ext_func(const_data, &ocf_io, NULL, req);
}

void ocf_blktrace_update_token(const ocf_blktrace_const_data_t *const_data,
				ocf_volume_t volume, uint64_t addr,
				ocf_forward_token_t token)
{
	struct ocf_request *req = ocf_req_forward_token_to_req(token);
	ocf_io_t ocf_io = {
		.volume = volume,
		.addr = (addr & 0x1) ? req->addr : addr,
		.dir = req->rw,
	};

	blktrace_ext_func(const_data, &ocf_io, NULL, req);

}

/* Deinit the volsim database */
void ocf_blktrace_volsim_destroy(ocf_volume_t volume)
{
	if (s_register.volsim_destroy) {
		s_register.volsim_destroy(volume);
	} else {
		ENV_BUG();
	}
}

/* Init the volsim database */
void ocf_blktrace_volsim_create(ocf_volume_t volume)
{
	if (s_register.volsim_create) {
		s_register.volsim_create(volume);
	} else {
		ENV_BUG();
	}
}
#endif
