/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 * @brief OCF API for updating and reseting statistics
 *
 * This file contains routines pertaining to manipulation of OCF IO statistics.
 */

#ifndef __OCF_STATS_H__
#define __OCF_STATS_H__

#include "ocf/ocf_prefetch_common.h"
#include "ocf/ocf_feedback_counters_def.h"

/**
 * Entire row of statistcs
 */
struct ocf_stat {
	/** Value */
	uint64_t value;
	/** percent x100 */
	uint64_t fraction;
};

/**
 * @brief Usage statistics in 4 KiB unit
 *
 * An example of presenting statistics:
 * <pre>
 * ╔══════════════════╤══════════╤═══════╤═════════════╗
 * ║ Usage statistics │  Count   │   %   │   Units     ║
 * ╠══════════════════╪══════════╪═══════╪═════════════╣
 * ║ Occupancy        │       20 │  50.0 │ 4KiB blocks ║
 * ║ Free             │       20 │  50.0 │ 4KiB blocks ║
 * ║ Clean            │       15 │  75.0 │ 4KiB blocks ║
 * ║ Dirty            │        5 │  25.0 │ 4KiB blocks ║
 * ╚══════════════════╧══════════╧═══════╧═════════════╝
 * </pre>
 */
struct ocf_stats_usage {
	struct ocf_stat occupancy;
	struct ocf_stat free;
	struct ocf_stat clean;
	struct ocf_stat dirty;
};

/**
 * @brief Requests statistcs
 *
 * An example of presenting statistics:
 * <pre>
 * ╔══════════════════════╤═══════╤═══════╤══════════╗
 * ║ Request statistics   │ Count │   %   │ Units    ║
 * ╠══════════════════════╪═══════╪═══════╪══════════╣
 * ║ Read hits            │    10 │   4.5 │ Requests ║
 * ║ Read deferred        │     0 │   0.0 │ Requests ║
 * ║ Read partial misses  │     1 │   0.5 │ Requests ║
 * ║ Read full misses     │   211 │  95.0 │ Requests ║
 * ║ Read total           │   222 │ 100.0 │ Requests ║
 * ╟──────────────────────┼───────┼───────┼──────────╢
 * ║ Write hits           │     0 │   0.0 │ Requests ║
 * ║ Write deferred       │     0 │   0.0 │ Requests ║
 * ║ Write partial misses │     0 │   0.0 │ Requests ║
 * ║ Write full misses    │     0 │   0.0 │ Requests ║
 * ║ Write total          │     0 │   0.0 │ Requests ║
 * ╟──────────────────────┼───────┼───────┼──────────╢
 * ║ Pass-Through reads   │     0 │   0.0 │ Requests ║
 * ║ Pass-Through writes  │     0 │   0.0 │ Requests ║
 * ║ Serviced requests    │   222 │ 100.0 │ Requests ║
 * ╟──────────────────────┼───────┼───────┼──────────╢
 * ║ Total requests       │   222 │ 100.0 │ Requests ║
 * ╚══════════════════════╧═══════╧═══════╧══════════╝
 *
 * ╔═════════════════════╤═══════╤═══════╤══════════╗
 * ║ Prefetch statistics │ Count │   %   │ Units    ║
 * ╠═════════════════════╪═══════╪═══════╪══════════╣
 * ║ Prefetch: stream    │     0 │   0.0 │ Requests ║
 * ║ Prefetch total      │     0 │   0.0 │ Requests ║
 * ╚═════════════════════╧═══════╧═══════╧══════════╝
* </pre>
 */
#ifdef OCF_DEBUG_STATS
#define DBG_IO_PACKET_NO 12
#define DBG_IO_ALIGN_NO 4

typedef struct {
	struct ocf_stat chkpts_cnt;
	struct ocf_stat chkpts_alloc_free;
	struct ocf_stat chkpts_alloc_sub;
	struct ocf_stat chkpts_sub_comp;
	struct ocf_stat chkpts_comp_free;
	struct ocf_stat chkpts_push_back_cnt;
	struct ocf_stat chkpts_push_back_pop;
	struct ocf_stat chkpts_push_front_cnt;
	struct ocf_stat chkpts_push_front_pop;
} dbg_chkpts_stats_t;
#endif

struct ocf_stats_requests {
	struct ocf_stat rd_hits;
	struct ocf_stat rd_deferred;
	struct ocf_stat rd_partial_misses;
	struct ocf_stat rd_full_misses;
	struct ocf_stat rd_total;
	struct ocf_stat wr_hits;
	struct ocf_stat wr_deferred;
	struct ocf_stat wr_partial_misses;
	struct ocf_stat wr_full_misses;
	struct ocf_stat wr_total;
	struct ocf_stat rd_pt;
	struct ocf_stat wr_pt;
	struct ocf_stat serviced;
	struct ocf_stat total;
	struct ocf_stat prefetches[pa_id_num];
#ifdef OCF_DEBUG_STATS
	struct ocf_stat dbg_read_size[DBG_IO_PACKET_NO];
	struct ocf_stat dbg_write_size[DBG_IO_PACKET_NO];
	struct ocf_stat dbg_read_align[DBG_IO_ALIGN_NO];
	struct ocf_stat dbg_write_align[DBG_IO_ALIGN_NO];
	struct ocf_stat dbg_read_slow_path;
	struct ocf_stat dbg_write_slow_path;
	struct ocf_stat dbg_concurrent_requests;
	dbg_chkpts_stats_t dbg_chkpts_stats_core_rd;
	dbg_chkpts_stats_t dbg_chkpts_stats_core_wr;
	dbg_chkpts_stats_t dbg_chkpts_stats_cache_rd;
	dbg_chkpts_stats_t dbg_chkpts_stats_cache_wr;
	dbg_chkpts_stats_t dbg_chkpts_stats_ocf_rd;
	dbg_chkpts_stats_t dbg_chkpts_stats_ocf_wr;
#endif
};

/**
 * @brief Block statistics
 *
 * An example of presenting statistics:
 * <pre>
 * ╔════════════════════════════════════╤═══════╤═══════╤═════════════╗
 * ║ Block statistics                   │ Count │   %   │   Units     ║
 * ╠════════════════════════════════════╪═══════╪═══════╪═════════════╣
 * ║ Reads from core volume(s)          │   426 │ 100.0 │ 4KiB blocks ║
 * ║ Writes to core volume(s)           │     0 │   0.0 │ 4KiB blocks ║
 * ║ Total to/from core volume (s)      │   426 │ 100.0 │ 4KiB blocks ║
 * ╟────────────────────────────────────┼───────┼───────┼─────────────╢
 * ║ Reads from cache volume            │    13 │   3.0 │ 4KiB blocks ║
 * ║ Writes to cache volume             │   426 │  97.0 │ 4KiB blocks ║
 * ║ Total to/from cache volume         │   439 │ 100.0 │ 4KiB blocks ║
 * ╟────────────────────────────────────┼───────┼───────┼─────────────╢
 * ║ Reads from core(s)                 │   439 │ 100.0 │ 4KiB blocks ║
 * ║ Writes to core(s)                  │     0 │   0.0 │ 4KiB blocks ║
 * ║ Total to/from core(s)              │   439 │ 100.0 │ 4KiB blocks ║
 * ╚════════════════════════════════════╧═══════╧═══════╧═════════════╝
 * </pre>
 */
struct ocf_stats_blocks {
	struct ocf_stat core_volume_rd;
	struct ocf_stat core_volume_wr;
	struct ocf_stat core_volume_total;
	struct ocf_stat cache_volume_rd;
	struct ocf_stat cache_volume_wr;
	struct ocf_stat cache_volume_total;
	struct ocf_stat volume_rd;
	struct ocf_stat volume_wr;
	struct ocf_stat volume_total;
	struct ocf_stat pass_through_rd;
	struct ocf_stat pass_through_wr;
	struct ocf_stat pass_through_total;
	struct ocf_stat prefetch_core_rd[pa_id_num];
	struct ocf_stat prefetch_cache_rd[pa_id_num];
	struct ocf_stat prefetch_cache_wr[pa_id_num];
	#define X(cnt) struct ocf_stat ocf_alg_##cnt[pa_id_num];
		OCF_CNT_CACHE_ALG
	#undef X
	#define X(cnt) struct ocf_stat ocf_feedback_##cnt;
		OCF_CNT_CACHE_GLB
	#undef X
};

/**
 * @brief Errors statistics
 *
 * An example of presenting statistics:
 * <pre>
 * ╔════════════════════╤═══════╤═════╤══════════╗
 * ║ Error statistics   │ Count │  %  │ Units    ║
 * ╠════════════════════╪═══════╪═════╪══════════╣
 * ║ Cache read errors  │     0 │ 0.0 │ Requests ║
 * ║ Cache write errors │     0 │ 0.0 │ Requests ║
 * ║ Cache total errors │     0 │ 0.0 │ Requests ║
 * ╟────────────────────┼───────┼─────┼──────────╢
 * ║ Core read errors   │     0 │ 0.0 │ Requests ║
 * ║ Core write errors  │     0 │ 0.0 │ Requests ║
 * ║ Core total errors  │     0 │ 0.0 │ Requests ║
 * ╟────────────────────┼───────┼─────┼──────────╢
 * ║ Total errors       │     0 │ 0.0 │ Requests ║
 * ╚════════════════════╧═══════╧═════╧══════════╝
 * </pre>
 */
struct ocf_stats_errors {
	struct ocf_stat core_volume_rd;
	struct ocf_stat core_volume_wr;
	struct ocf_stat core_volume_total;
	struct ocf_stat cache_volume_rd;
	struct ocf_stat cache_volume_wr;
	struct ocf_stat cache_volume_total;
	struct ocf_stat total;
};

/**
 * @param Collect statistics for given cache
 *
 * @param cache Cache instance for which statistics will be collected
 * @param usage Usage statistics
 * @param req Request statistics
 * @param blocks Blocks statistics
 * @param errors Errors statistics
 *
 * @retval 0 Success
 * @retval Non-zero Error
 */
int ocf_stats_collect_cache(ocf_cache_t cache,
		struct ocf_stats_usage *usage,
		struct ocf_stats_requests *req,
		struct ocf_stats_blocks *blocks,
		struct ocf_stats_errors *errors);

/**
 * @param Collect statistics for given core
 *
 * @param core Core for which statistics will be collected
 * @param usage Usage statistics
 * @param req Request statistics
 * @param blocks Blocks statistics
 * @param errors Errors statistics
 *
 * @retval 0 Success
 * @retval Non-zero Error
 */
int ocf_stats_collect_core(ocf_core_t core,
		struct ocf_stats_usage *usage,
		struct ocf_stats_requests *req,
		struct ocf_stats_blocks *blocks,
		struct ocf_stats_errors *errors);

/**
 * @param Collect statistics for given ioclass
 *
 * @param core Core handle for which statistics will be collected
 * @param part_id Ioclass id for which statistics will be collected
 * @param usage Usage statistics
 * @param req Request statistics
 * @param blocks Blocks statistics
 *
 * @retval 0 Success
 * @retval Non-zero Error
 */
int ocf_stats_collect_part_core(ocf_core_t core, ocf_part_id_t part_id,
		struct ocf_stats_usage *usage, struct ocf_stats_requests *req,
		struct ocf_stats_blocks *blocks);

/**
 * @param Collect statistics for given ioclass
 *
 * @param cache Cache instance for which statistics will be collected
 * @param part_id Ioclass id for which statistics will be collected
 * @param usage Usage statistics
 * @param req Request statistics
 * @param blocks Blocks statistics
 *
 * @retval 0 Success
 * @retval Non-zero Error
 */
int ocf_stats_collect_part_cache(ocf_cache_t cache, ocf_part_id_t part_id,
		struct ocf_stats_usage *usage, struct ocf_stats_requests *req,
		struct ocf_stats_blocks *blocks);

/**
 * @brief Initialize or reset core statistics
 *
 * Initialize or reset counters used for statistics.
 *
 * @param[in] core Core handle
 */
void ocf_core_stats_initialize(ocf_core_t core);

/**
 * @brief Initialize or reset statistics of all cores in cache
 *
 * Initialize or reset counters used for statistics.
 *
 * @param[in] cache Cache handle
 *
 * @retval 0 Success
 * @retval Non-zero Error
 */
int ocf_core_stats_initialize_all(ocf_cache_t cache);

#endif /* __OCF_STATS_H__ */
