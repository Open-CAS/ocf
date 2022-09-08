/*
 * Copyright(c) 2012-2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __CACHE_ENGINE_H_
#define __CACHE_ENGINE_H_

struct ocf_thread_priv;
struct ocf_request;

#define LOOKUP_HIT 5
#define LOOKUP_MISS 6
#define LOOKUP_REMAPPED 8

typedef enum {
	/* modes inherited from user API */
	ocf_req_cache_mode_wt = ocf_cache_mode_wt,
	ocf_req_cache_mode_wb = ocf_cache_mode_wb,
	ocf_req_cache_mode_wa = ocf_cache_mode_wa,
	ocf_req_cache_mode_pt = ocf_cache_mode_pt,
	ocf_req_cache_mode_wi = ocf_cache_mode_wi,
	ocf_req_cache_mode_wo = ocf_cache_mode_wo,

	/* internal modes */
	ocf_req_cache_mode_fast,
		/*!< Fast path */
	ocf_req_cache_mode_d2c,
		/*!< Direct to Core - pass through to core without
				touching cacheline metadata */

	ocf_req_cache_mode_max,
} ocf_req_cache_mode_t;

typedef int (*ocf_engine_cb)(struct ocf_request *req);

struct ocf_io_if {
	ocf_engine_cb cbs[2]; /* READ and WRITE */

	const char *name;
};

void ocf_resolve_effective_cache_mode(ocf_cache_t cache,
		ocf_core_t core, struct ocf_request *req);

const char *ocf_get_io_iface_name(ocf_req_cache_mode_t cache_mode);

bool ocf_req_cache_mode_has_lazy_write(ocf_req_cache_mode_t mode);

bool ocf_fallback_pt_is_on(ocf_cache_t cache);

struct ocf_request *ocf_engine_pop_req(struct ocf_queue *q);

int ocf_engine_hndl_req(struct ocf_request *req);

#define OCF_FAST_PATH_YES	7
#define OCF_FAST_PATH_NO	13

int ocf_engine_hndl_fast_req(struct ocf_request *req);

void ocf_engine_hndl_discard_req(struct ocf_request *req);

void ocf_engine_hndl_ops_req(struct ocf_request *req);

#endif
