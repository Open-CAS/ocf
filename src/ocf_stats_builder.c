/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_priv.h"
#include "ocf_env.h"
#include "metadata/metadata.h"
#include "engine/cache_engine.h"
#include "utils/utils_user_part.h"
#include "utils/utils_cache_line.h"
#include "utils/utils_stats.h"

#ifdef OCF_DEBUG_STATS
static void _fill_dbg_check_pts_stats(dbg_chkpts_stats_t *req, const chkpts_core_stats_t *cpstts)
{
	uint64_t cnt = cpstts->chkpts_cnt;
	uint64_t alloc_free = 0;
	uint64_t alloc_sub = 0;
	uint64_t sub_comp = 0;
	uint64_t comp_free = 0;
	uint64_t push_back_cnt = cpstts->chkpts_push_back_cnt;
	uint64_t push_back_pop = 0;
	uint64_t push_front_cnt = cpstts->chkpts_push_front_cnt;
	uint64_t push_front_pop = 0;

	if (cnt) {
		alloc_free = env_ticks_to_nsecs(cpstts->chkpts_alloc_free / cnt);
		alloc_sub = env_ticks_to_nsecs(cpstts->chkpts_alloc_sub / cnt);
		sub_comp = env_ticks_to_nsecs(cpstts->chkpts_sub_comp / cnt);
		comp_free = env_ticks_to_nsecs(cpstts->chkpts_comp_free / cnt);
	}
	if (push_back_cnt) {
		push_back_pop = env_ticks_to_nsecs(cpstts->chkpts_push_back_pop / push_back_cnt);
	}
	if (push_front_cnt) {
		push_front_pop = env_ticks_to_nsecs(cpstts->chkpts_push_front_pop / push_front_cnt);
	}

	_set(&req->chkpts_cnt, cnt, cnt);
	_set(&req->chkpts_alloc_free, alloc_free, alloc_free);
	_set(&req->chkpts_alloc_sub, alloc_sub, alloc_free);
	_set(&req->chkpts_sub_comp, sub_comp, alloc_free);
	_set(&req->chkpts_comp_free, comp_free, alloc_free);
	_set(&req->chkpts_push_back_cnt, push_back_cnt, cnt);
	_set(&req->chkpts_push_back_pop, push_back_pop, alloc_free);
	_set(&req->chkpts_push_front_cnt, push_front_cnt, cnt);
	_set(&req->chkpts_push_front_pop, push_front_pop, alloc_free);
}
#endif

static void _fill_req(struct ocf_stats_requests *req, struct ocf_stats_core *s)
{
	pf_algo_id_t pa;
	uint64_t serviced = s->read_reqs.total + s->write_reqs.total;
	uint64_t total = serviced + s->read_reqs.pass_through +
			s->write_reqs.pass_through;
	uint64_t hit;
	uint64_t prefetch_total = 0;

	/* Reads Section */
	hit = s->read_reqs.total - (s->read_reqs.full_miss +
			s->read_reqs.partial_miss + s->read_reqs.deferred);
	_set(&req->rd_hits, hit, total);
	_set(&req->rd_deferred, s->read_reqs.deferred, total);
	_set(&req->rd_partial_misses, s->read_reqs.partial_miss, total);
	_set(&req->rd_full_misses, s->read_reqs.full_miss, total);
	_set(&req->rd_total, s->read_reqs.total, total);

	/* Write Section */
	hit = s->write_reqs.total - (s->write_reqs.full_miss +
			s->write_reqs.partial_miss + s->write_reqs.deferred);
	_set(&req->wr_hits, hit, total);
	_set(&req->wr_deferred, s->write_reqs.deferred, total);
	_set(&req->wr_partial_misses, s->write_reqs.partial_miss, total);
	_set(&req->wr_full_misses, s->write_reqs.full_miss, total);
	_set(&req->wr_total, s->write_reqs.total, total);

	/* Prefetch Section */
	for_each_valid_pa_id(pa) {
		prefetch_total += s->prefetch_reqs[pa].total;
	}
	for_each_valid_pa_id(pa) {
		_set(&req->prefetches[pa], s->prefetch_reqs[pa].total, prefetch_total);
	}

	/* Pass-Through section */
	_set(&req->rd_pt, s->read_reqs.pass_through, total);
	_set(&req->wr_pt, s->write_reqs.pass_through, total);

	/* Summary */
	_set(&req->serviced, serviced, total);
	_set(&req->total, total, total);

#ifdef OCF_DEBUG_STATS
	/* Debug */
	{
		int i;
		for (i = 0; i < IO_PACKET_NO; i++) {
			_set(&req->dbg_read_size[i], s->debug_stat.read_size[i], total);
			_set(&req->dbg_write_size[i], s->debug_stat.write_size[i], total);
		}
		for (i = 0; i < IO_ALIGN_NO; i++) {
			_set(&req->dbg_read_align[i], s->debug_stat.read_align[i], total);
			_set(&req->dbg_write_align[i], s->debug_stat.write_align[i], total);
		}
		_set(&req->dbg_read_slow_path, s->debug_stat.read_slow_path, total);
		_set(&req->dbg_write_slow_path, s->debug_stat.write_slow_path, total);
		_set(&req->dbg_concurrent_requests, s->debug_stat.concurrent_requests, total);

		_fill_dbg_check_pts_stats(&req->dbg_chkpts_stats_core_rd, &s->debug_stat.chkpts_stats_core_rd);
		_fill_dbg_check_pts_stats(&req->dbg_chkpts_stats_core_wr, &s->debug_stat.chkpts_stats_core_wr);
		_fill_dbg_check_pts_stats(&req->dbg_chkpts_stats_cache_rd, &s->debug_stat.chkpts_stats_cache_rd);
		_fill_dbg_check_pts_stats(&req->dbg_chkpts_stats_cache_wr, &s->debug_stat.chkpts_stats_cache_wr);
		_fill_dbg_check_pts_stats(&req->dbg_chkpts_stats_ocf_rd, &s->debug_stat.chkpts_stats_ocf_rd);
		_fill_dbg_check_pts_stats(&req->dbg_chkpts_stats_ocf_wr, &s->debug_stat.chkpts_stats_ocf_wr);
	}
#endif
}

static void _fill_req_part(struct ocf_stats_requests *req,
		struct ocf_stats_io_class *s)
{
	pf_algo_id_t pa;
	uint64_t serviced = s->read_reqs.total + s->write_reqs.total;
	uint64_t total = serviced + s->read_reqs.pass_through +
			s->write_reqs.pass_through;
	uint64_t hit;
	uint64_t prefetch_total = 0;

	/* Reads Section */
	hit = s->read_reqs.total - (s->read_reqs.full_miss +
			s->read_reqs.partial_miss + s->read_reqs.deferred);
	_set(&req->rd_hits, hit, total);
	_set(&req->rd_deferred, s->read_reqs.deferred, total);
	_set(&req->rd_partial_misses, s->read_reqs.partial_miss, total);
	_set(&req->rd_full_misses, s->read_reqs.full_miss, total);
	_set(&req->rd_total, s->read_reqs.total, total);

	/* Write Section */
	hit = s->write_reqs.total - (s->write_reqs.full_miss +
			s->write_reqs.partial_miss + s->write_reqs.deferred);
	_set(&req->wr_hits, hit, total);
	_set(&req->wr_deferred, s->write_reqs.deferred, total);
	_set(&req->wr_partial_misses, s->write_reqs.partial_miss, total);
	_set(&req->wr_full_misses, s->write_reqs.full_miss, total);
	_set(&req->wr_total, s->write_reqs.total, total);

	/* Prefetch Section */
	for_each_valid_pa_id(pa) {
		prefetch_total += s->prefetch_reqs[pa].total;
	}
	for_each_valid_pa_id(pa)
		_set(&req->prefetches[pa], s->prefetch_reqs[pa].total, prefetch_total);

	/* Pass-Through section */
	_set(&req->rd_pt, s->read_reqs.pass_through, total);
	_set(&req->wr_pt, s->write_reqs.pass_through, total);

	/* Summary */
	_set(&req->serviced, serviced, total);
	_set(&req->total, total, total);
}

static void _fill_blocks(struct ocf_stats_blocks *blocks,
		const struct ocf_stats_core *s)
{
	uint64_t rd, wr, total;
	uint64_t pa_rd, pa_wr;
	uint64_t pa_v, pa_total;
	pf_algo_id_t pa;

	/* Core volume */
	rd = _bytes4k(s->core_volume.read);
	wr = _bytes4k(s->core_volume.write);
	total = rd + wr;
	/* OCF: add all prefetcher core blocks to the core total */
	for_each_valid_pa_id(pa) {
		pa_rd = _bytes4k(s->prefetch_core_blocks[pa].read);
		total += pa_rd;
	}
	for_each_valid_pa_id(pa) {
		pa_rd = _bytes4k(s->prefetch_core_blocks[pa].read);
		_set(&blocks->prefetch_core_rd[pa], pa_rd, total);
	}
	_set(&blocks->core_volume_rd, rd, total);
	_set(&blocks->core_volume_wr, wr, total);
	_set(&blocks->core_volume_total, total, total);

	/* Cache volume */
	rd = _bytes4k(s->cache_volume.read);
	wr = _bytes4k(s->cache_volume.write);
	total = rd + wr;
	/* OCF: add all prefetcher cache blocks to the cache total */
	for_each_valid_pa_id(pa) {
		pa_rd = _bytes4k(s->prefetch_cache_blocks[pa].read);
		pa_wr = _bytes4k(s->prefetch_cache_blocks[pa].write);
		total += pa_rd + pa_wr;
	}
	for_each_valid_pa_id(pa) {
		pa_rd = _bytes4k(s->prefetch_cache_blocks[pa].read);
		_set(&blocks->prefetch_cache_rd[pa], pa_rd, total);
		pa_wr = _bytes4k(s->prefetch_cache_blocks[pa].write);
		_set(&blocks->prefetch_cache_wr[pa], pa_wr, total);
	}
	for_each_valid_pa_id(pa) {
		pa_total = _bytes4k(s->ocf_feedback.alg_cnt[pa].cache_written_blocks);
		#define X(cnt) do { \
				pa_v = _bytes4k(s->ocf_feedback.alg_cnt[pa].cnt); \
				_set(&blocks->ocf_alg_##cnt[pa], pa_v, pa_total); \
			} while (0);
			OCF_CNT_CACHE_ALG
		#undef X
	}
	pa_total = _bytes4k(s->ocf_feedback.g_total_read_blocks);
	#define X(cnt) do { \
			pa_v = _bytes4k(s->ocf_feedback.cnt); \
			_set(&blocks->ocf_feedback_##cnt, pa_v, pa_total); \
			} while (0);
		OCF_CNT_CACHE_GLB
	#undef X

	_set(&blocks->cache_volume_rd, rd, total);
	_set(&blocks->cache_volume_wr, wr, total);
	_set(&blocks->cache_volume_total, total, total);

	/* Core (cache volume) */
	rd = _bytes4k(s->core.read);
	wr = _bytes4k(s->core.write);
	total = rd + wr;
	_set(&blocks->volume_rd, rd, total);
	_set(&blocks->volume_wr, wr, total);
	_set(&blocks->volume_total, total, total);

	/* Pass Through */
	rd = _bytes4k(s->pass_through_blocks.read);
	wr = _bytes4k(s->pass_through_blocks.write);
	total = rd + wr;
	_set(&blocks->pass_through_rd, rd, total);
	_set(&blocks->pass_through_wr, wr, total);
	_set(&blocks->pass_through_total, total, total);
}

static void _fill_blocks_part(struct ocf_stats_blocks *blocks,
		const struct ocf_stats_io_class *s)
{
	uint64_t rd, wr, total;
	uint64_t pa_rd, pa_wr;
	uint64_t pa_v, pa_total;
	pf_algo_id_t pa;

	/* Core volume */
	rd = _bytes4k(s->core_blocks.read);
	wr = _bytes4k(s->core_blocks.write);
	total = rd + wr;
	/* OCF: add all prefetcher core blocks to the core total */
	for_each_valid_pa_id(pa) {
		pa_rd = _bytes4k(s->prefetch_core_blocks[pa].read);
		total += pa_rd;
	}
	for_each_valid_pa_id(pa) {
		pa_rd = _bytes4k(s->prefetch_core_blocks[pa].read);
		_set(&blocks->prefetch_core_rd[pa], pa_rd, total);
	}
	_set(&blocks->core_volume_rd, rd, total);
	_set(&blocks->core_volume_wr, wr, total);
	_set(&blocks->core_volume_total, total, total);

	/* Cache volume */
	rd = _bytes4k(s->cache_blocks.read);
	wr = _bytes4k(s->cache_blocks.write);
	total = rd + wr;
	/* OCF: add all prefetcher cache blocks to the cache total */
	for_each_valid_pa_id(pa) {
		pa_rd = _bytes4k(s->prefetch_cache_blocks[pa].read);
		pa_wr = _bytes4k(s->prefetch_cache_blocks[pa].write);
		total += pa_rd + pa_wr;
	}
	for_each_valid_pa_id(pa) {
		pa_rd = _bytes4k(s->prefetch_cache_blocks[pa].read);
		_set(&blocks->prefetch_cache_rd[pa], pa_rd, total);
		pa_wr = _bytes4k(s->prefetch_cache_blocks[pa].write);
		_set(&blocks->prefetch_cache_wr[pa], pa_wr, total);
	}
	for_each_valid_pa_id(pa) {
		pa_total = _bytes4k(s->ocf_feedback.alg_cnt[pa].cache_written_blocks);
		#define X(cnt) do { \
				pa_v = _bytes4k(s->ocf_feedback.alg_cnt[pa].cnt); \
				_set(&blocks->ocf_alg_##cnt[pa], pa_v, pa_total); \
			} while (0);
			OCF_CNT_CACHE_ALG
		#undef X
	}
	pa_total = _bytes4k(s->ocf_feedback.g_total_read_blocks);
	#define X(cnt) do { \
			pa_v = _bytes4k(s->ocf_feedback.cnt); \
			_set(&blocks->ocf_feedback_##cnt, pa_v, pa_total); \
			} while (0);
		OCF_CNT_CACHE_GLB
	#undef X
	_set(&blocks->cache_volume_rd, rd, total);
	_set(&blocks->cache_volume_wr, wr, total);
	_set(&blocks->cache_volume_total, total, total);

	/* Core (cache volume) */
	rd = _bytes4k(s->blocks.read);
	wr = _bytes4k(s->blocks.write);
	total = rd + wr;
	_set(&blocks->volume_rd, rd, total);
	_set(&blocks->volume_wr, wr, total);
	_set(&blocks->volume_total, total, total);

	/* Pass Through */
	rd = _bytes4k(s->pass_through_blocks.read);
	wr = _bytes4k(s->pass_through_blocks.write);
	total = rd + wr;
	_set(&blocks->pass_through_rd, rd, total);
	_set(&blocks->pass_through_wr, wr, total);
	_set(&blocks->pass_through_total, total, total);
}

static void _fill_errors(struct ocf_stats_errors *errors,
		struct ocf_stats_core *s)
{
	uint64_t rd, wr, total;

	rd = s->core_errors.read;
	wr = s->core_errors.write;
	total = rd + wr;
	_set(&errors->core_volume_rd, rd, total);
	_set(&errors->core_volume_wr, wr, total);
	_set(&errors->core_volume_total, total, total);

	rd = s->cache_errors.read;
	wr = s->cache_errors.write;
	total = rd + wr;
	_set(&errors->cache_volume_rd, rd, total);
	_set(&errors->cache_volume_wr, wr, total);
	_set(&errors->cache_volume_total, total, total);

	total = s->core_errors.read + s->core_errors.write +
		s->cache_errors.read + s->cache_errors.write;

	_set(&errors->total, total, total);
}

static void _accumulate_block(struct ocf_stats_block *to,
		const struct ocf_stats_block *from)
{
	to->read += from->read;
	to->write += from->write;
}

static void _accumulate_ocf_feedback(struct ocf_stats_cache_feedback *to,
		const struct ocf_stats_cache_feedback *from)
{
	pf_algo_id_t pa;
	for_each_valid_pa_id(pa) {
		#define X(cnt) to->alg_cnt[pa].cnt += from->alg_cnt[pa].cnt;
			OCF_CNT_CACHE_ALG
		#undef X
	}
	#define X(cnt) to->cnt += from->cnt;
		OCF_CNT_CACHE_GLB
	#undef X
}

static void _accumulate_reqs(struct ocf_stats_req *to,
		const struct ocf_stats_req *from)
{
	to->full_miss += from->full_miss;
	to->deferred += from->deferred;
	to->partial_miss += from->partial_miss;
	to->total += from->total;
	to->pass_through += from->pass_through;
}

static void _accumulate_errors(struct ocf_stats_error *to,
		const struct ocf_stats_error *from)
{
	to->read += from->read;
	to->write += from->write;
}

struct io_class_stats_context {
	struct ocf_stats_io_class *stats;
	ocf_part_id_t part_id;
};

static int _accumulate_io_class_stats(ocf_core_t core, void *cntx)
{
	int result;
	struct ocf_stats_io_class stats;
	struct ocf_stats_io_class *total =
		((struct io_class_stats_context*)cntx)->stats;
	ocf_part_id_t part_id = ((struct io_class_stats_context*)cntx)->part_id;
	pf_algo_id_t pa;

	result = ocf_core_io_class_get_stats(core, part_id, &stats);
	if (result)
		return result;

	total->occupancy_clines += stats.occupancy_clines;
	total->dirty_clines += stats.dirty_clines;
	total->free_clines = stats.free_clines;

	_accumulate_block(&total->cache_blocks, &stats.cache_blocks);
	_accumulate_block(&total->core_blocks, &stats.core_blocks);
	_accumulate_block(&total->blocks, &stats.blocks);
	_accumulate_block(&total->pass_through_blocks, &stats.pass_through_blocks);
	_accumulate_ocf_feedback(&total->ocf_feedback, &stats.ocf_feedback);

	_accumulate_reqs(&total->read_reqs, &stats.read_reqs);
	_accumulate_reqs(&total->write_reqs, &stats.write_reqs);

	/* OCF: prefetch section */
	for_each_valid_pa_id(pa) {
		_accumulate_reqs(&total->prefetch_reqs[pa], &stats.prefetch_reqs[pa]);
		_accumulate_block(&total->prefetch_cache_blocks[pa], &stats.prefetch_cache_blocks[pa]);
		_accumulate_block(&total->prefetch_core_blocks[pa], &stats.prefetch_core_blocks[pa]);
	}

	return 0;
}

static void _ocf_stats_part_fill(ocf_cache_t cache, ocf_part_id_t part_id,
		struct ocf_stats_io_class *stats , struct ocf_stats_usage *usage,
		struct ocf_stats_requests *req, struct ocf_stats_blocks *blocks)
{
	uint64_t cache_size, cache_line_size;

	cache_line_size = ocf_cache_get_line_size(cache);
	cache_size = ocf_cache_get_line_count(cache);

	if (usage) {
		_set(&usage->occupancy,
			_lines4k(stats->occupancy_clines, cache_line_size),
			_lines4k(cache_size, cache_line_size));

		_set(&usage->free,
			_lines4k(stats->free_clines, cache_line_size),
			_lines4k(cache_size, cache_line_size));

		_set(&usage->clean,
			_lines4k(stats->occupancy_clines - stats->dirty_clines,
				cache_line_size),
			_lines4k(stats->occupancy_clines, cache_line_size));

		_set(&usage->dirty,
			_lines4k(stats->dirty_clines, cache_line_size),
			_lines4k(stats->occupancy_clines, cache_line_size));
	}

	if (req)
		_fill_req_part(req, stats);

	if (blocks)
		_fill_blocks_part(blocks, stats);
}

int ocf_stats_collect_part_core(ocf_core_t core, ocf_part_id_t part_id,
		struct ocf_stats_usage *usage, struct ocf_stats_requests *req,
		struct ocf_stats_blocks *blocks)
{
	struct ocf_stats_io_class s;
	ocf_cache_t cache;
	int result = 0;

	OCF_CHECK_NULL(core);

	cache = ocf_core_get_cache(core);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (part_id > OCF_IO_CLASS_ID_MAX)
		return -OCF_ERR_INVAL;

	_ocf_stats_zero(usage);
	_ocf_stats_zero(req);
	_ocf_stats_zero(blocks);

	result = ocf_core_io_class_get_stats(core, part_id, &s);
	if (result)
		return result;

	_ocf_stats_part_fill(cache, part_id, &s, usage, req, blocks);

	return result;
}

int ocf_stats_collect_part_cache(ocf_cache_t cache, ocf_part_id_t part_id,
		struct ocf_stats_usage *usage, struct ocf_stats_requests *req,
		struct ocf_stats_blocks *blocks)
{
	struct io_class_stats_context ctx;
	struct ocf_stats_io_class s = {};
	int result = 0;

	OCF_CHECK_NULL(cache);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (part_id > OCF_IO_CLASS_ID_MAX)
		return -OCF_ERR_INVAL;

	_ocf_stats_zero(usage);
	_ocf_stats_zero(req);
	_ocf_stats_zero(blocks);

	ctx.part_id = part_id;
	ctx.stats = &s;

	result = ocf_core_visit(cache, _accumulate_io_class_stats, &ctx, true);
	if (result)
		return result;

	_ocf_stats_part_fill(cache, part_id, &s, usage, req, blocks);

	return result;
}

int ocf_stats_collect_core(ocf_core_t core,
		struct ocf_stats_usage *usage,
		struct ocf_stats_requests *req,
		struct ocf_stats_blocks *blocks,
		struct ocf_stats_errors *errors)
{
	ocf_cache_t cache;
	uint64_t cache_occupancy, cache_size, cache_line_size;
	struct ocf_stats_core *s;
	int result;

	OCF_CHECK_NULL(core);

	s = env_vmalloc(sizeof(*s));
	if (!s)
		return -OCF_ERR_NO_MEM;

	cache = ocf_core_get_cache(core);

	if (ocf_cache_is_standby(cache)) {
		result = -OCF_ERR_CACHE_STANDBY;
		goto mem_free;
	}

	result = ocf_core_get_stats(core, s);
	if (result)
		goto mem_free;

	cache_line_size = ocf_cache_get_line_size(cache);
	cache_size = ocf_cache_get_line_count(cache);
	cache_occupancy = ocf_get_cache_occupancy(cache);

	_ocf_stats_zero(usage);
	_ocf_stats_zero(req);
	_ocf_stats_zero(blocks);
	_ocf_stats_zero(errors);

	if (usage) {
		_set(&usage->occupancy,
			_lines4k(s->cache_occupancy, cache_line_size),
			_lines4k(cache_size, cache_line_size));

		_set(&usage->free,
			_lines4k(cache_size - cache_occupancy, cache_line_size),
			_lines4k(cache_size, cache_line_size));

		_set(&usage->clean,
			_lines4k(s->cache_occupancy - s->dirty, cache_line_size),
			_lines4k(s->cache_occupancy, cache_line_size));

		_set(&usage->dirty,
			_lines4k(s->dirty, cache_line_size),
			_lines4k(s->cache_occupancy, cache_line_size));
	}

	if (req)
		_fill_req(req, s);

	if (blocks)
		_fill_blocks(blocks, s);

	if (errors)
		_fill_errors(errors, s);

mem_free:
	env_vfree(s);
	return result;
}

#ifdef OCF_DEBUG_STATS
static void _accumulate_dbg_check_pts_stats(chkpts_core_stats_t *dest, const chkpts_core_stats_t *src)
{
	dest->chkpts_cnt += src->chkpts_cnt;
	dest->chkpts_alloc_free += src->chkpts_alloc_free;
	dest->chkpts_alloc_sub += src->chkpts_alloc_sub;
	dest->chkpts_sub_comp += src->chkpts_sub_comp;
	dest->chkpts_comp_free += src->chkpts_comp_free;
	dest->chkpts_push_back_cnt += src->chkpts_push_back_cnt;
	dest->chkpts_push_back_pop += src->chkpts_push_back_pop;
	dest->chkpts_push_front_cnt += src->chkpts_push_front_cnt;
	dest->chkpts_push_front_pop += src->chkpts_push_front_pop;
}
#endif

static int _accumulate_stats(ocf_core_t core, void *cntx)
{
	struct ocf_stats_core stats, *total = cntx;
	int result;
	pf_algo_id_t pa;

	result = ocf_core_get_stats(core, &stats);
	if (result)
		return result;

	_accumulate_block(&total->cache_volume, &stats.cache_volume);
	_accumulate_block(&total->core_volume, &stats.core_volume);
	_accumulate_block(&total->core, &stats.core);
	_accumulate_block(&total->pass_through_blocks, &stats.pass_through_blocks);

	_accumulate_ocf_feedback(&total->ocf_feedback, &stats.ocf_feedback);

	_accumulate_reqs(&total->read_reqs, &stats.read_reqs);
	_accumulate_reqs(&total->write_reqs, &stats.write_reqs);

	_accumulate_errors(&total->cache_errors, &stats.cache_errors);
	_accumulate_errors(&total->core_errors, &stats.core_errors);

	/* OCF: prefetch section */
	for_each_valid_pa_id(pa) {
		_accumulate_reqs(&total->prefetch_reqs[pa], &stats.prefetch_reqs[pa]);
		_accumulate_block(&total->prefetch_cache_blocks[pa], &stats.prefetch_cache_blocks[pa]);
		_accumulate_block(&total->prefetch_core_blocks[pa], &stats.prefetch_core_blocks[pa]);
	}

#ifdef OCF_DEBUG_STATS
	/* Debug */
	{
		int i;
		for (i = 0; i < IO_PACKET_NO; i++) {
			total->debug_stat.read_size[i] += stats.debug_stat.read_size[i];
			total->debug_stat.write_size[i] += stats.debug_stat.write_size[i];
		}
		for (i = 0; i < IO_ALIGN_NO; i++) {
			total->debug_stat.read_align[i] += stats.debug_stat.read_align[i];
			total->debug_stat.write_align[i] += stats.debug_stat.write_align[i];
		}
		total->debug_stat.read_slow_path += stats.debug_stat.read_slow_path;
		total->debug_stat.write_slow_path += stats.debug_stat.write_slow_path;
		total->debug_stat.concurrent_requests += stats.debug_stat.concurrent_requests;

		_accumulate_dbg_check_pts_stats(&total->debug_stat.chkpts_stats_core_rd, &stats.debug_stat.chkpts_stats_core_rd);
		_accumulate_dbg_check_pts_stats(&total->debug_stat.chkpts_stats_core_wr, &stats.debug_stat.chkpts_stats_core_wr);
		_accumulate_dbg_check_pts_stats(&total->debug_stat.chkpts_stats_cache_rd, &stats.debug_stat.chkpts_stats_cache_rd);
		_accumulate_dbg_check_pts_stats(&total->debug_stat.chkpts_stats_cache_wr, &stats.debug_stat.chkpts_stats_cache_wr);
		_accumulate_dbg_check_pts_stats(&total->debug_stat.chkpts_stats_ocf_rd, &stats.debug_stat.chkpts_stats_ocf_rd);
		_accumulate_dbg_check_pts_stats(&total->debug_stat.chkpts_stats_ocf_wr, &stats.debug_stat.chkpts_stats_ocf_wr);
	}
#endif

	return 0;
}

int ocf_stats_collect_cache(ocf_cache_t cache,
		struct ocf_stats_usage *usage,
		struct ocf_stats_requests *req,
		struct ocf_stats_blocks *blocks,
		struct ocf_stats_errors *errors)
{
	uint64_t cache_line_size;
	struct ocf_cache_info info;
	struct ocf_stats_core *s;
	int result;

	OCF_CHECK_NULL(cache);

	s = env_vzalloc(sizeof(*s));
	if (!s)
		return -OCF_ERR_NO_MEM;

	if (ocf_cache_is_standby(cache)) {
		result = -OCF_ERR_CACHE_STANDBY;
		goto mem_free;
	}

	result = ocf_cache_get_info(cache, &info);
	if (result)
		goto mem_free;

	cache_line_size = ocf_cache_get_line_size(cache);

	_ocf_stats_zero(usage);
	_ocf_stats_zero(req);
	_ocf_stats_zero(blocks);
	_ocf_stats_zero(errors);

	result = ocf_core_visit(cache, _accumulate_stats, s, true);
	if (result)
		goto mem_free;

	if (usage) {
		_set(&usage->occupancy,
			_lines4k(info.occupancy, cache_line_size),
			_lines4k(info.size, cache_line_size));

		_set(&usage->free,
			_lines4k(info.size - info.occupancy, cache_line_size),
			_lines4k(info.size, cache_line_size));

		_set(&usage->clean,
			_lines4k(info.occupancy - info.dirty, cache_line_size),
			_lines4k(info.size, cache_line_size));

		_set(&usage->dirty,
			_lines4k(info.dirty, cache_line_size),
			_lines4k(info.size, cache_line_size));
	}

	if (req)
		_fill_req(req, s);

	if (blocks)
		_fill_blocks(blocks, s);

	if (errors)
		_fill_errors(errors, s);

mem_free:
	env_vfree(s);
	return result;
}
