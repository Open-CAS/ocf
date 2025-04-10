/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ocf/ocf_feedback_counters.h"
#include "../ocf_cache_priv.h"
#include "../ocf_core_priv.h"
#include "../ocf_request.h"

/* -------------------------------------------- */
/* Helpers */
/* -------------------------------------------- */

#define CCNT(core) 	\
	struct ocf_core_ocf_counters_cache_feedback *ccnt = \
	(struct ocf_core_ocf_counters_cache_feedback *) \
	&core->counters->part_counters[0].ocf_feedback
#define RCNT(req)  \
	struct ocf_req_ocf_counters_cache_feedback *rcnt = \
	(struct ocf_req_ocf_counters_cache_feedback *) \
	(&req->ocf_cache_feedback_counters)

/* -------------------------------------------- */
/* Promote request-counters to core-counters */
/* -------------------------------------------- */

static void promote_req_to_core(
	ocf_core_t core, struct ocf_request *req, size_t cacheline_size_bytes)
{
	RCNT(req);
	CCNT(core);
	env_atomic64 *pcnt;
	uint64_t req_cachelines;
	pf_algo_id_t pa_id;

	for_each_pa_id(pa_id) {
	#define X(cnt) \
			pcnt = &ccnt->alg_cnt[pa_id].cnt; \
			req_cachelines = rcnt->alg_cnt[pa_id].cnt; \
			if (req_cachelines) env_atomic64_add(cacheline_size_bytes * req_cachelines, pcnt); \
			rcnt->alg_cnt[pa_id].cnt = 0;
		OCF_CNT_CACHE_ALG_DISCOUNTABLE
	#undef X
	}
}

/* -------------------------------------------- */
/* Counting Helpers */
/* -------------------------------------------- */

#if OCF_CCNT_ATOMIC
#define CCNT_PA_GET(pa_id, cnt)	env_atomic64_read(&ccnt->alg_cnt[pa_id].cnt)
#define CCNT_G_GET(cnt)	        env_atomic64_read(&ccnt->cnt)
#define CCNT_PA_SET(pa_id, cnt, _va)	env_atomic64_set(&ccnt->alg_cnt[pa_id].cnt, _va)
#define CCNT_G_SET(cnt, _va)	        env_atomic64_set(&ccnt->cnt, _va)
#else
#define CCNT_PA_GET(pa_id, cnt)	(ccnt->alg_cnt[pa_id].cnt)
#define CCNT_G_GET(cnt)	        (ccnt->cnt)
#define CCNT_PA_SET(pa_id, cnt, _va)	(ccnt->alg_cnt[pa_id].cnt = _va)
#define CCNT_G_SET(cnt, _va)	        (ccnt->cnt = _va)
#endif

#if OCF_CCNT_ATOMIC
#define CCNT_PA_ADD(pa_id, cnt) env_atomic64_add(bytes, &ccnt->alg_cnt[pa_id].cnt)
#define CCNT_G_ADD(cnt)         env_atomic64_add(bytes, &ccnt->cnt)
#else
#define CCNT_PA_ADD(pa_id, cnt) ccnt->alg_cnt[pa_id].cnt += bytes
#define CCNT_G_ADD(cnt)         ccnt->cnt += bytes
#endif

/* -------------------------------------------- */
/* Counting Functions */
/* -------------------------------------------- */

/* Request counters */
#define X(cnt) \
void ocf_cache_feedback_counters_req_##cnt##_inc( \
	ocf_core_t core, struct ocf_request *req, pf_algo_id_t pa_id) \
{ \
	RCNT(req); \
	if (!PA_ID_VALID(pa_id) || (1 != OCF_CNT_ENABLED)) \
		return; \
	rcnt->alg_cnt[pa_id].cnt++; \
}
OCF_CNT_CACHE_ALG_DISCOUNTABLE
#undef X

#define X(cnt) \
void ocf_cache_feedback_counters_core_##cnt##_add( \
	ocf_core_t core, pf_algo_id_t pa_id, uint64_t bytes) \
{ \
	CCNT(core); \
	if (!PA_ID_VALID(pa_id) || (1 != OCF_CNT_ENABLED)) \
		return; \
	CCNT_PA_ADD(pa_id, cnt); \
}
OCF_CNT_CACHE_ALG
#undef X

#define X(cnt) \
void ocf_cache_feedback_counters_core_##cnt##_add( \
	ocf_core_t core, uint64_t bytes) \
{ \
	CCNT(core); \
	if (1 != OCF_CNT_ENABLED) \
		return; \
	CCNT_G_ADD(cnt); \
}
OCF_CNT_CACHE_GLB
#undef X

/* --------------------------------- */
/* Counters Getters */
/* --------------------------------- */

#define X(cnt) \
uint64_t ocf_cache_feedback_counters_core_##cnt##_get( \
	ocf_core_t core, pf_algo_id_t pa_id) \
{ \
	CCNT(core); \
	if (!PA_ID_VALID(pa_id) || (1 != OCF_CNT_ENABLED)) \
		return 0; \
	return CCNT_PA_GET(pa_id, cnt); \
}
OCF_CNT_CACHE_ALG
#undef X

#define X(cnt) \
uint64_t ocf_cache_feedback_counters_core_##cnt##_get(ocf_core_t core) \
{ \
	CCNT(core); \
	if (1 != OCF_CNT_ENABLED) \
		return 0; \
	return CCNT_G_GET(cnt); \
}
OCF_CNT_CACHE_GLB
#undef X

/* --------------------------------- */
/* Counters Maintenance Functions */
/* --------------------------------- */

#define X(cnt) \
static void core_##cnt##_discount( \
	ocf_core_t core, pf_algo_id_t pa_id, uint8_t pct) \
{ \
	uint64_t value; \
	CCNT(core); \
	if (!PA_ID_VALID(pa_id) || (1 != OCF_CNT_ENABLED)) \
		return; \
	value = CCNT_PA_GET(pa_id, cnt); \
	CCNT_PA_SET(pa_id, cnt, value * pct / 100); \
}
OCF_CNT_CACHE_ALG
#undef X

#define X(cnt) \
static void core_##cnt##_discount( \
	ocf_core_t core, uint8_t pct) \
{ \
	uint64_t value; \
	CCNT(core); \
	if (1 != OCF_CNT_ENABLED) \
		return; \
	value = CCNT_G_GET(cnt); \
	CCNT_G_SET(cnt, value * pct / 100); \
}
OCF_CNT_CACHE_GLB
#undef X

void ocf_cache_feedback_counters_core_reset(ocf_core_t core)
{
	pf_algo_id_t pa_id;
	for_each_pa_id(pa_id) {
		#define X(cnt) core_##cnt##_discount(core, pa_id, 0);
			OCF_CNT_CACHE_ALG
		#undef X
	}
	#define X(cnt) core_##cnt##_discount(core, 0);
		OCF_CNT_CACHE_GLB
	#undef X
}
void ocf_cache_feedback_counters_core_discount(ocf_core_t core, uint8_t pct)
{
	pf_algo_id_t pa_id;
	for_each_pa_id(pa_id) {
		#define X(cnt) core_##cnt##_discount(core, pa_id, pct);
			OCF_CNT_CACHE_ALG_DISCOUNTABLE
		#undef X
	}
	#define X(cnt) core_##cnt##_discount(core, pct);
		OCF_CNT_CACHE_GLB_DISCOUNTABLE
	#undef X
}

void ocf_cache_feedback_counters_core_req_promote(ocf_core_t core, struct ocf_request *req)
{
	uint64_t cacheline_size_bytes = ocf_cache_get_line_size(ocf_core_get_cache(core));
	promote_req_to_core(core, req, cacheline_size_bytes);
}
