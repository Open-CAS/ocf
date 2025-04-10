/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PREFETCH_COMMON_H__
#define __OCF_PREFETCH_COMMON_H__

#define OCF_PA_ID_MAX_BITS	3
#define OCF_PA_ID_MAX		((1 << OCF_PA_ID_MAX_BITS) - 1)

#define MAX_TOTAL_PF		(8 * MiB)
#define MAX_SINGLE_PF(len)	(OCF_MAX(64 * KiB, len))

/* Prefetch Algorithm ID
 * Addind/Removing values require update OCF_PA_ID_NUM in
 * tests/functional/pyocf/types/stats/shared.py
 *
 * Definition must be ordered.
 */

#define OCF_MPE_TEST	0

#define OCF_PF_ALGOS_PROD_X \
	X(readahead) \
	X(stream) \
	X(upper)
#define OCF_PF_ALGOS_RESEARCH_X \
	X(skip1m)
#define OCF_PF_ALGOS_NON_PROD_X \
	OCF_PF_ALGOS_RESEARCH_X
/* keep OCF_PF_ALGOS_PROD_X as first */
#define OCF_PF_ALGOS_ALL_X \
	OCF_PF_ALGOS_PROD_X \
	OCF_PF_ALGOS_NON_PROD_X

#if OCF_MPE_TEST
#define OCF_PF_ALGOS_X \
	OCF_PF_ALGOS_ALL_X
#else
#define OCF_PF_ALGOS_X \
	OCF_PF_ALGOS_PROD_X
#endif

/* make sure all prefetchers have id enums, even if unused, in order to maintain valid
 * and simple code for compilation (avoid many ifdefs in prefetchers' code).
 */
typedef enum {
	#define X(alg) pa_id_##alg,
	OCF_PF_ALGOS_X
	pa_id_num,
	pa_id_none = pa_id_num,
#if OCF_MPE_TEST
#else
	OCF_PF_ALGOS_NON_PROD_X
#endif
	#undef X
} pf_algo_id_t;

typedef enum {
	pa_mask_none = 0,
	#define X(alg) pa_mask_##alg = 1 << pa_id_##alg,
	OCF_PF_ALGOS_X
	#undef X
} pf_algo_mask_t;

#ifdef OCF_PF_ALGOS_DEFINE
/* Prefetch algorithms names */
const char *ocf_pa_names[] = {
	#define X(alg) #alg,
	OCF_PF_ALGOS_X };
	#undef X
#endif

/* Prefetch Algorithm - default list
 * Define DEFAULT_PREFETCH_ALGO_USE_ALL to use all existing prefetch algorithms
 * Alternatively, set the mask of DEFAULT_PREFETCH_ALGO below
 *
 * Note: DEFAULT_PREFETCH_ALGO can not be overridden in runtime, it specifies the
 * algorithms the system is "aware of".  Core-specific prefetchers are subset of
 * this value.
 */

#if OCF_MPE_TEST
#define DEFAULT_PREFETCH_ALGO_USE_ALL
#endif

//#define DEFAULT_PREFETCH_ALGO_USE_ALL
#ifdef DEFAULT_PREFETCH_ALGO_USE_ALL
static const pf_algo_mask_t pa_mask_all =
	#define X(alg) pa_mask_##alg |
	OCF_PF_ALGOS_X
	#undef X
	pa_mask_none;
#define DEFAULT_PREFETCH_ALGO	(pa_mask_all)
#else
//#define DEFAULT_PREFETCH_ALGO	(pa_mask_none)
#define DEFAULT_PREFETCH_ALGO	(pa_mask_stream | pa_mask_upper)
#endif

/* The macros below work as follows for 4-bit sample DEFAULT_PREFETCH_ALGO:
 * DEFAULT_PREFETCH_ALGO  FIRST  LAST
 * 0000                   0      0	// pa_mask_none
 * 0001                   0      0	// pa_mask_readahead
 * 0010                   1      1	// pa_mask_stream
 * 0011                   0      1	// pa_mask_stream | pa_mask_readahead
 *
 * for_each_valid_pa_id()  iterates only the compile-time (DEFAULT_PREFETCH_ALGO) set values.
 * for_each_enabled_pa_id() iterates only (enabled_mask & DEFAULT_PREFETCH_ALGO).
 */

#define PA_MASK_FIRST_BIT	((DEFAULT_PREFETCH_ALGO != 0) ?      __builtin_ctz((unsigned int)(DEFAULT_PREFETCH_ALGO)) : 0)
#define PA_MASK_LAST_BIT	((DEFAULT_PREFETCH_ALGO != 0) ? 31 - __builtin_clz((unsigned int)(DEFAULT_PREFETCH_ALGO)) : 0)

#define PA_ID_VALID(_pa)	((_pa) < pa_id_num)
#define PA_ID_VALID_AND_REAL(_pa)	(PA_ID_VALID(_pa) && (_pa) != pa_id_upper)
#define PA_ID_ENABLED(_pa, enabled_mask) \
	((1 << ((int)(_pa))) & enabled_mask)

#define for_each_pa_id(_pa) \
	for (_pa = PA_MASK_FIRST_BIT; _pa <= PA_MASK_LAST_BIT; _pa++)

#define for_each_valid_pa_id(_pa) \
	for_each_pa_id(_pa) \
		if (PA_ID_ENABLED(_pa, DEFAULT_PREFETCH_ALGO))

#define for_each_enabled_pa_id(_pa, enabled_mask) \
	for_each_pa_id(_pa) \
		if (PA_ID_ENABLED(_pa, enabled_mask & DEFAULT_PREFETCH_ALGO))

#endif /* __OCF_PREFETCH_COMMON_H__ */
