/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_FEEDBACK_COUNTERS_H__
#define __OCF_FEEDBACK_COUNTERS_H__

#include "ocf/ocf.h"

/* -------------------------------------------- */
struct ocf_request;

/* --------------------------------- */
/* Feedback Counters Core Getters */
#define X(cnt) \
uint64_t ocf_cache_feedback_counters_core_##cnt##_get( \
	ocf_core_t core, pf_algo_id_t pa_id);
OCF_CNT_CACHE_ALG
#undef X
#define X(cnt) \
uint64_t ocf_cache_feedback_counters_core_##cnt##_get( \
	ocf_core_t core);
OCF_CNT_CACHE_GLB
#undef X

/* Increment function for specific counter on request per counted event on a cacheline */
#define X(cnt) \
void ocf_cache_feedback_counters_req_##cnt##_inc( \
	ocf_core_t core, struct ocf_request *req, pf_algo_id_t pa_id);
OCF_CNT_CACHE_ALG_DISCOUNTABLE
#undef X

/* Core-Global counters are updated once per request, based on multiple cachelines */
#define X(cnt) \
void ocf_cache_feedback_counters_core_##cnt##_add( \
	ocf_core_t core, pf_algo_id_t pa_id, uint64_t bytes);
OCF_CNT_CACHE_ALG
#undef X
#define X(cnt) \
void ocf_cache_feedback_counters_core_##cnt##_add( \
	ocf_core_t core, uint64_t bytes);
OCF_CNT_CACHE_GLB
#undef X

/* -------------------------------------------- */

void ocf_cache_feedback_counters_core_reset(ocf_core_t core);
void ocf_cache_feedback_counters_core_discount(ocf_core_t core, uint8_t pct);

void ocf_cache_feedback_counters_core_req_promote(ocf_core_t core, struct ocf_request *req);


#endif /* __OCF_FEEDBACK_COUNTERS_H__ */
