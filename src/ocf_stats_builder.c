/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_priv.h"
#include "metadata/metadata.h"
#include "engine/cache_engine.h"
#include "utils/utils_part.h"
#include "utils/utils_cache_line.h"

#define _ocf_stats_zero(stats) \
	do { \
		if (stats) { \
			typeof(*stats) zero = { { 0 } }; \
			*stats = zero; \
		} \
	} while (0)

static uint64_t _percentage(uint64_t numerator, uint64_t denominator)
{
	uint64_t result;
	if (denominator) {
		result = 1000 * numerator / denominator;
	} else {
		result = 0;
	}
	return result;
}

static uint64_t _lines4k(uint64_t size,
		ocf_cache_line_size_t cache_line_size)
{
	long unsigned int result;

	result = size * (cache_line_size / 4096);

	return result;
}

static uint64_t _bytes4k(uint64_t bytes)
{
	return (bytes + 4095UL) >> 12;
}

static uint64_t _get_cache_occupancy(ocf_cache_t cache)
{
	uint64_t result = 0;
	uint32_t i;

	for (i = 0; i != OCF_CORE_MAX; ++i) {
		if (!env_bit_test(i, cache->conf_meta->valid_object_bitmap))
			continue;

		result += env_atomic_read(
				&cache->core_runtime_meta[i].cached_clines);
	}

	return result;
}

static void _set(struct ocf_stat *stat, uint64_t value, uint64_t denominator)
{
	stat->value = value;
	stat->percent = _percentage(value, denominator);
}

static void _fill_req(struct ocf_stats_requests *req, struct ocf_stats_core *s)
{
	uint64_t serviced = s->read_reqs.total + s->write_reqs.total;
	uint64_t total = serviced + s->read_reqs.pass_through +
			s->write_reqs.pass_through;
	uint64_t hit;

	/* Reads Section */
	hit = s->read_reqs.total - (s->read_reqs.full_miss +
			s->read_reqs.partial_miss);
	_set(&req->rd_hits, hit, total);
	_set(&req->rd_partial_misses, s->read_reqs.partial_miss, total);
	_set(&req->rd_full_misses, s->read_reqs.full_miss, total);
	_set(&req->rd_total, s->read_reqs.total, total);

	/* Write Section */
	hit = s->write_reqs.total - (s->write_reqs.full_miss +
					s->write_reqs.partial_miss);
	_set(&req->wr_hits, hit, total);
	_set(&req->wr_partial_misses, s->write_reqs.partial_miss, total);
	_set(&req->wr_full_misses, s->write_reqs.full_miss, total);
	_set(&req->wr_total, s->write_reqs.total, total);

	/* Pass-Through section */
	_set(&req->rd_pt, s->read_reqs.pass_through, total);
	_set(&req->wr_pt, s->write_reqs.pass_through, total);

	/* Summary */
	_set(&req->serviced, serviced, total);
	_set(&req->total, total, total);
}

static void _fill_req_io_class(struct ocf_stats_requests *req,
		struct ocf_stats_io_class *s, uint64_t denominator)
{
	uint64_t serviced = s->read_reqs.total + s->write_reqs.total;
	uint64_t total = serviced + s->read_reqs.pass_through +
			s->write_reqs.pass_through;
	uint64_t hit;

	/* Reads Section */
	hit = s->read_reqs.total - (s->read_reqs.full_miss +
			s->read_reqs.partial_miss);
	_set(&req->rd_hits, hit, denominator);
	_set(&req->rd_partial_misses, s->read_reqs.partial_miss, denominator);
	_set(&req->rd_full_misses, s->read_reqs.full_miss, denominator);
	_set(&req->rd_total, s->read_reqs.total, denominator);

	/* Write Section */
	hit = s->write_reqs.total - (s->write_reqs.full_miss +
					s->write_reqs.partial_miss);
	_set(&req->wr_hits, hit, denominator);
	_set(&req->wr_partial_misses, s->write_reqs.partial_miss, denominator);
	_set(&req->wr_full_misses, s->write_reqs.full_miss, denominator);
	_set(&req->wr_total, s->write_reqs.total, denominator);

	/* Pass-Through section */
	_set(&req->rd_pt, s->read_reqs.pass_through, denominator);
	_set(&req->wr_pt, s->write_reqs.pass_through, denominator);

	/* Summary */
	_set(&req->serviced, serviced, denominator);
	_set(&req->total, total, denominator);
}

static void _fill_blocks(struct ocf_stats_blocks *blocks,
		struct ocf_stats_core *s)
{
	uint64_t rd, wr, total;

	/* Core data object */
	rd = _bytes4k(s->core_obj.read);
	wr = _bytes4k(s->core_obj.write);
	total = rd + wr;
	_set(&blocks->core_obj_rd, rd, total);
	_set(&blocks->core_obj_wr, wr, total);
	_set(&blocks->core_obj_total, total, total);

	/* Cache data object */
	rd = _bytes4k(s->cache_obj.read);
	wr = _bytes4k(s->cache_obj.write);
	total = rd + wr;
	_set(&blocks->cache_obj_rd, rd, total);
	_set(&blocks->cache_obj_wr, wr, total);
	_set(&blocks->cache_obj_total, total, total);

	/* Core (cache volume) */
	rd = _bytes4k(s->core.read);
	wr = _bytes4k(s->core.write);
	total = rd + wr;
	_set(&blocks->volume_rd, rd, total);
	_set(&blocks->volume_wr, wr, total);
	_set(&blocks->volume_total, total, total);
}

static void _fill_errors(struct ocf_stats_errors *errors,
		struct ocf_stats_core *s)
{
	uint64_t rd, wr, total;

	rd = s->core_errors.read;
	wr = s->core_errors.write;
	total = rd + wr;
	_set(&errors->core_obj_rd, rd, total);
	_set(&errors->core_obj_wr, wr, total);
	_set(&errors->core_obj_total, total, total);

	rd = s->cache_errors.read;
	wr = s->cache_errors.write;
	total = rd + wr;
	_set(&errors->cache_obj_rd, rd, total);
	_set(&errors->cache_obj_wr, wr, total);
	_set(&errors->cache_obj_total, total, total);

	total = s->core_errors.read + s->core_errors.write +
		s->cache_errors.read + s->cache_errors.write;

	_set(&errors->total, total, total);
}

int ocf_stats_collect_core(ocf_core_t core,
		struct ocf_stats_usage *usage,
		struct ocf_stats_requests *req,
		struct ocf_stats_blocks *blocks,
		struct ocf_stats_errors *errors)
{
	ocf_cache_t cache;
	uint64_t cache_occupancy, cache_size, cache_line_size;
	struct ocf_stats_core s;
	int result;

	OCF_CHECK_NULL(core);

	result = ocf_core_get_stats(core, &s);
	if (result)
		return result;

	cache = ocf_core_get_cache(core);
	cache_line_size = ocf_cache_get_line_size(cache);
	cache_size = cache->conf_meta->cachelines;
	cache_occupancy = _get_cache_occupancy(cache);

	_ocf_stats_zero(usage);
	_ocf_stats_zero(req);
	_ocf_stats_zero(blocks);
	_ocf_stats_zero(errors);

	if (usage) {
		_set(&usage->occupancy,
			_lines4k(s.cache_occupancy, cache_line_size),
			_lines4k(cache_size, cache_line_size));

		_set(&usage->free,
			_lines4k(cache_size - cache_occupancy, cache_line_size),
			_lines4k(cache_size, cache_line_size));

		_set(&usage->clean,
			_lines4k(s.cache_occupancy - s.dirty, cache_line_size),
			_lines4k(s.cache_occupancy, cache_line_size));

		_set(&usage->dirty,
			_lines4k(s.dirty, cache_line_size),
			_lines4k(s.cache_occupancy, cache_line_size));
	}

	if (req)
		_fill_req(req, &s);

	if (blocks)
		_fill_blocks(blocks, &s);

	if (errors)
		_fill_errors(errors, &s);

	return 0;
}

static void _accumulate_block(struct ocf_stats_block *to,
		const struct ocf_stats_block *from)
{
	to->read += from->read;
	to->write += from->write;
}

static void _accumulate_reqs(struct ocf_stats_req *to,
		const struct ocf_stats_req *from)
{
	to->full_miss += from->full_miss;
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

static int _accumulate_stats(ocf_core_t core, void *cntx)
{
	struct ocf_stats_core stats, *total = cntx;
	int result;

	result = ocf_core_get_stats(core, &stats);
	if (result)
		return result;

	_accumulate_block(&total->cache_obj, &stats.cache_obj);
	_accumulate_block(&total->core_obj, &stats.core_obj);
	_accumulate_block(&total->core, &stats.core);

	_accumulate_reqs(&total->read_reqs, &stats.read_reqs);
	_accumulate_reqs(&total->write_reqs, &stats.write_reqs);

	_accumulate_errors(&total->cache_errors, &stats.cache_errors);
	_accumulate_errors(&total->core_errors, &stats.core_errors);

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
	struct ocf_stats_core s = { 0 };
	int result;

	OCF_CHECK_NULL(cache);

	result = ocf_cache_get_info(cache, &info);
	if (result)
		return result;

	cache_line_size = ocf_cache_get_line_size(cache);

	_ocf_stats_zero(usage);
	_ocf_stats_zero(req);
	_ocf_stats_zero(blocks);
	_ocf_stats_zero(errors);

	result = ocf_core_visit(cache, _accumulate_stats, &s, true);
	if (result)
		return result;

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
		_fill_req(req, &s);

	if (blocks)
		_fill_blocks(blocks, &s);

	if (errors)
		_fill_errors(errors, &s);

	return 0;
}

static int _accumulate_stats_io_class(ocf_core_t core, void *cntx)
{
	struct ocf_stats_io_class stats, *total = cntx;
	ocf_cache_t cache;
	struct ocf_user_part *part;
	ocf_part_id_t part_id;
	int result;

	cache = ocf_core_get_cache(core);

	for_each_part(cache, part, part_id) {
		if (!ocf_part_is_valid(part))
			continue;

		result = ocf_core_io_class_get_stats(core, part_id, &stats);
		if (result)
			return result;

		_accumulate_block(&total->blocks, &stats.blocks);

		_accumulate_reqs(&total->read_reqs, &stats.read_reqs);
		_accumulate_reqs(&total->write_reqs, &stats.write_reqs);
	}

	return 0;
}

static void _fill_usage_io_class(ocf_cache_t cache,
		struct ocf_stats_io_class *s, struct ocf_stats_io_class *denominator,
		struct ocf_stats_usage *usage)
{
	uint64_t cache_line_size = ocf_cache_get_line_size(cache);
	uint64_t cache_size = cache->conf_meta->cachelines;
	uint64_t cache_occupancy = _get_cache_occupancy(cache);

	_set(&usage->free,
		_lines4k(cache_size - cache_occupancy, cache_line_size),
		_lines4k(cache_size, cache_line_size));

	_set(&usage->occupancy,
		_lines4k(s->occupancy_clines, cache_line_size),
		_lines4k(cache_size, cache_line_size));

	_set(&usage->clean,
		_lines4k(s->occupancy_clines - s->dirty_clines, cache_line_size),
		_lines4k(s->occupancy_clines, cache_line_size));

	_set(&usage->dirty,
		_lines4k(s->dirty_clines, cache_line_size),
		_lines4k(s->occupancy_clines, cache_line_size));
}

int ocf_stats_collect_io_class_core(ocf_core_t core,
		ocf_part_id_t io_class,
		struct ocf_stats_usage *usage,
		struct ocf_stats_requests *req,
		struct ocf_stats_blocks_io_class *blocks)
{
	ocf_cache_t cache;
	struct ocf_stats_io_class s = {}, denominator = {};
	int result;

	OCF_CHECK_NULL(core);
	cache = ocf_core_get_cache(core);

	if (io_class < OCF_IO_CLASS_ID_MIN || io_class > OCF_IO_CLASS_ID_MAX)
		return -OCF_ERR_INVAL;

	/* Gather all io classes stats for denominators */
	result = ocf_core_visit(cache, _accumulate_stats_io_class,
			&denominator, true);
	if (result)
		return result;

	result = ocf_core_io_class_get_stats(core, io_class, &s);
	if (result)
		return result;

	_ocf_stats_zero(usage);
	_ocf_stats_zero(req);
	_ocf_stats_zero(blocks);

	if (usage)
		_fill_usage_io_class(cache, &s, &denominator, usage);

	if (req)
		_fill_req_io_class(req, &s, denominator.read_reqs.total +
				denominator.write_reqs.total);

	if (blocks) {
		_set(&blocks->rd,
				_bytes4k(s.blocks.read),
				_bytes4k(denominator.blocks.read));
		_set(&blocks->wr,
				_bytes4k(s.blocks.write),
				_bytes4k(denominator.blocks.write));
	}

	return 0;
}

static int _accumulate_stats_io_class_core(ocf_core_t core,
		ocf_part_id_t part_id, void *cntx)
{
	struct ocf_stats_io_class s, *total = cntx;
	int result;

	result = ocf_core_io_class_get_stats(core, part_id, &s);
	if (result)
		return result;

	total->occupancy_clines += s.occupancy_clines;
	total->free_clines += s.free_clines;
	total->dirty_clines += s.dirty_clines;

	_accumulate_block(&total->blocks, &s.blocks);

	_accumulate_reqs(&total->read_reqs, &s.read_reqs);
	_accumulate_reqs(&total->write_reqs, &s.write_reqs);

	return 0;
}

int ocf_stats_collect_io_class_core_all(ocf_cache_t cache,
		ocf_part_id_t io_class,
		struct ocf_stats_usage *usage,
		struct ocf_stats_requests *req,
		struct ocf_stats_blocks_io_class *blocks)
{
	struct ocf_stats_io_class s = {}, denominator = {};
	int result;

	OCF_CHECK_NULL(cache);

	if (io_class < OCF_IO_CLASS_ID_MIN || io_class > OCF_IO_CLASS_ID_MAX)
		return -OCF_ERR_INVAL;

	/* Gather all io classes stats for denominators */
	result = ocf_core_visit(cache, _accumulate_stats_io_class,
			&denominator, true);
	if (result)
		return result;

	_ocf_stats_zero(usage);
	_ocf_stats_zero(req);
	_ocf_stats_zero(blocks);

	/* Gather stats for given io class */
	result = ocf_io_class_core_visit(cache, io_class,
			_accumulate_stats_io_class_core, &s);
	if (result)
		return result;

	if (usage)
		_fill_usage_io_class(cache, &s, &denominator, usage);

	if (req)
		_fill_req_io_class(req, &s, denominator.read_reqs.total +
				denominator.write_reqs.total);

	if (blocks) {
		_set(&blocks->rd,
				_bytes4k(s.blocks.read),
				_bytes4k(denominator.blocks.read));
		_set(&blocks->wr,
				_bytes4k(s.blocks.write),
				_bytes4k(denominator.blocks.write));
	}

	return 0;
}
