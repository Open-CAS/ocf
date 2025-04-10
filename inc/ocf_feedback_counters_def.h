/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_FEEDBACK_COUNTERS_DEF_H__
#define __OCF_FEEDBACK_COUNTERS_DEF_H__

#define OCF_CNT_ENABLED		1
#define OCF_CCNT_ATOMIC		1

/* -------------------------------------------- */
/* Counter Names */
/* -------------------------------------------- */

#define OCF_CNT_CACHE_ALG_DISCOUNTABLE \
	X(cache_read_blocks) \
	X(cache_overwritten_blocks) \
	X(cache_evicted_blocks)

#define OCF_CNT_CACHE_ALG \
	X(core_read_blocks) \
	X(cache_written_blocks) \
	OCF_CNT_CACHE_ALG_DISCOUNTABLE

#define OCF_CNT_CACHE_GLB_DISCOUNTABLE \
	X(g_cache_miss_blocks) \
	X(g_total_read_blocks)

#define OCF_CNT_CACHE_GLB \
	OCF_CNT_CACHE_GLB_DISCOUNTABLE

/* -------------------------------------------- */
/* Structs */
/* -------------------------------------------- */

/* request counters are updated during handling request processing (submission).
 * units of counters are cachelines, rather than blocks/bytes. */
#define X(cnt) uint16_t cnt;
struct ocf_req_ocf_counters_cache_alg {
	OCF_CNT_CACHE_ALG_DISCOUNTABLE
};
struct ocf_req_ocf_counters_cache_feedback {
	struct ocf_req_ocf_counters_cache_alg alg_cnt[pa_id_num];
};
#undef X


#endif /* __OCF_FEEDBACK_COUNTERS_DEF_H__ */
