/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __CACHE_ENGINE_H_
#define __CACHE_ENGINE_H_

#include "../ocf_request.h"

struct ocf_thread_priv;

#define LOOKUP_HIT 5
#define LOOKUP_MISS 6
#define LOOKUP_REMAPPED 8
#define LOOKUP_HIT_INVALID 9

static inline ocf_req_cache_mode_t ocf_cache_mode_to_req_cache_mode(
		ocf_cache_mode_t mode)
{
	return (ocf_req_cache_mode_t)mode;
}

struct ocf_io_if {
	ocf_req_cb cbs[2]; /* READ and WRITE */

	const char *name;
};

void ocf_resolve_effective_cache_mode(ocf_cache_t cache,
		ocf_core_t core, struct ocf_request *req);

const char *ocf_get_io_iface_name(ocf_req_cache_mode_t cache_mode);

bool ocf_req_cache_mode_has_lazy_write(ocf_req_cache_mode_t mode);

bool ocf_fallback_pt_is_on(ocf_cache_t cache);

int ocf_engine_hndl_req(struct ocf_request *req);

#define OCF_FAST_PATH_YES	7
#define OCF_FAST_PATH_NO	13

int ocf_engine_hndl_fast_req(struct ocf_request *req);

void ocf_engine_hndl_flush_req(struct ocf_request *req);

void ocf_engine_hndl_discard_req(struct ocf_request *req);

#endif
