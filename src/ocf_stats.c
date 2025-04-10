/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_priv.h"
#include "metadata/metadata.h"
#include "engine/cache_engine.h"
#include "utils/utils_user_part.h"
#include "utils/utils_cache_line.h"
#include "ocf/ocf_feedback_counters.h"

#ifdef OCF_DEBUG_STATS
static void ocf_stats_debug_init(struct ocf_counters_debug *stats)
{
	int i;

	for (i = 0; i < IO_PACKET_NO; i++) {
		env_atomic64_set(&stats->read_size[i], 0);
		env_atomic64_set(&stats->write_size[i], 0);
	}

	for (i = 0; i < IO_ALIGN_NO; i++) {
		env_atomic64_set(&stats->read_align[i], 0);
		env_atomic64_set(&stats->write_align[i], 0);
	}

	env_atomic64_set(&stats->read_slow_path, 0);
	env_atomic64_set(&stats->write_slow_path, 0);
}
#endif

static void ocf_stats_req_init(struct ocf_counters_req *stats)
{
	env_atomic64_set(&stats->full_miss, 0);
	env_atomic64_set(&stats->deferred, 0);
	env_atomic64_set(&stats->partial_miss, 0);
	env_atomic64_set(&stats->total, 0);
	env_atomic64_set(&stats->pass_through, 0);
}

static void ocf_stats_block_init(struct ocf_counters_block *stats)
{
	env_atomic64_set(&stats->read_bytes, 0);
	env_atomic64_set(&stats->write_bytes, 0);
}

static void ocf_stats_part_init(struct ocf_counters_part *stats)
{
	pf_algo_id_t pa;
	ocf_stats_req_init(&stats->read_reqs);
	ocf_stats_req_init(&stats->write_reqs);
	for_each_valid_pa_id(pa) {
		ocf_stats_req_init(&stats->prefetch_reqs[pa]);
		ocf_stats_block_init(&stats->prefetch_cache_blocks[pa]);
		ocf_stats_block_init(&stats->prefetch_core_blocks[pa]);
	}

	ocf_stats_block_init(&stats->blocks);
	ocf_stats_block_init(&stats->core_blocks);
	ocf_stats_block_init(&stats->cache_blocks);
	ocf_stats_block_init(&stats->pass_through_blocks);
}

static void ocf_stats_error_init(struct ocf_counters_error *stats)
{
	env_atomic_set(&stats->read, 0);
	env_atomic_set(&stats->write, 0);
}

void ocf_stats_block_update(struct ocf_counters_block *counters, int dir,
		uint64_t bytes)
{
	switch (dir) {
		case OCF_READ:
			env_atomic64_add(bytes, &counters->read_bytes);
			break;
		case OCF_WRITE:
			env_atomic64_add(bytes, &counters->write_bytes);
			break;
		default:
			ENV_BUG();
	}
}

void ocf_core_stats_vol_block_update(ocf_core_t core, ocf_part_id_t part_id,
		int dir, uint64_t bytes, pf_algo_id_t pa_id)
{
	struct ocf_counters_block *counters =
		&core->counters->part_counters[part_id].blocks;

	ocf_stats_block_update(counters, dir, bytes);
}

void ocf_core_stats_cache_block_update(ocf_core_t core, ocf_part_id_t part_id,
		int dir, uint64_t bytes, pf_algo_id_t pa_id)
{
	struct ocf_counters_block *counters =
		&core->counters->part_counters[part_id].cache_blocks;

	if (PA_ID_VALID(pa_id)) {
		counters = &core->counters->part_counters[part_id].
					    prefetch_cache_blocks[pa_id];
	}

	ocf_stats_block_update(counters, dir, bytes);

	if (OCF_WRITE == dir) {
		/* count for prefetchers or admission */
		ocf_cache_feedback_counters_core_cache_written_blocks_add(core, pa_id, bytes);
	}
}

void ocf_core_stats_core_block_update(ocf_core_t core, ocf_part_id_t part_id,
		int dir, uint64_t bytes, pf_algo_id_t pa_id)
{
	struct ocf_counters_block *counters =
		&core->counters->part_counters[part_id].core_blocks;

	if (PA_ID_VALID(pa_id)) {
		counters = &core->counters->part_counters[part_id].
					    prefetch_core_blocks[pa_id];
	}

	ocf_stats_block_update(counters, dir, bytes);

	if (OCF_READ == dir) {
		/* count for prefetchers or admission */
		ocf_cache_feedback_counters_core_core_read_blocks_add(core, pa_id, bytes);
	}
}

void ocf_core_stats_pt_block_update(ocf_core_t core, ocf_part_id_t part_id,
		int dir, uint64_t bytes)
{
	struct ocf_counters_block *counters =
		&core->counters->part_counters[part_id].pass_through_blocks;

	ocf_stats_block_update(counters, dir, bytes);
}

void ocf_core_stats_request_update(ocf_core_t core, ocf_part_id_t part_id,
		uint8_t dir, uint64_t hit_no, uint32_t core_line_count,
		pf_algo_id_t pa_id, uint8_t deferred)
{
	struct ocf_counters_req *counters;
	uint64_t miss_bytes, total_bytes, cline_size_bytes;

	switch (dir) {
		case OCF_READ:
			counters = &core->counters->part_counters[part_id].read_reqs;
			if (PA_ID_VALID(pa_id))
				counters = &core->counters->part_counters[part_id].
							    prefetch_reqs[pa_id];
			break;
		case OCF_WRITE:
			ENV_BUG_ON(PA_ID_VALID(pa_id));
			counters = &core->counters->part_counters[part_id].write_reqs;
			break;
		default:
			ENV_BUG();
	}

	env_atomic64_inc(&counters->total);

	if (hit_no == 0)
		env_atomic64_inc(&counters->full_miss);
	else if (hit_no < core_line_count)
		env_atomic64_inc(&counters->partial_miss);
	else if (deferred)
		env_atomic64_inc(&counters->deferred);

	/* core reads which are not prefetch - prefetch core reads should not be
	 * counted as misses.
	 *
	 *  NOTE: unaligned i/o (not on 4KB boundary) - in order to count accurately,
	 *   we need to check exact range. Perhaps not needed. Let's wait to see the
	 *   impact and decide later if improving accuracy is worth it.
	 */
	if ((OCF_READ == dir) && !PA_ID_VALID(pa_id)) {
		cline_size_bytes = ocf_cache_get_line_size(ocf_core_get_cache(core));
		total_bytes = (uint64_t)core_line_count * (uint32_t)cline_size_bytes;	/* The cast is to avoid overflow */
		miss_bytes = (core_line_count - hit_no) * cline_size_bytes;
		ocf_cache_feedback_counters_core_g_cache_miss_blocks_add(core, miss_bytes);
		ocf_cache_feedback_counters_core_g_total_read_blocks_add(core, total_bytes);
	}
}

void ocf_core_stats_request_pt_update(ocf_core_t core, ocf_part_id_t part_id,
		uint8_t dir, uint64_t hit_no, uint64_t core_line_count)
{
	struct ocf_counters_req *counters;

	switch (dir) {
		case OCF_READ:
			counters = &core->counters->part_counters[part_id].read_reqs;
			break;
		case OCF_WRITE:
			counters = &core->counters->part_counters[part_id].write_reqs;
			break;
		default:
			ENV_BUG();
	}

	env_atomic64_inc(&counters->pass_through);
}

static void _ocf_core_stats_error_update(struct ocf_counters_error *counters,
		uint8_t dir)
{
	switch (dir) {
		case OCF_READ:
			env_atomic_inc(&counters->read);
			break;
		case OCF_WRITE:
			env_atomic_inc(&counters->write);
			break;
		default:
			ENV_BUG();
	}
}

void ocf_core_stats_core_error_update(ocf_core_t core, uint8_t dir)
{
	struct ocf_counters_error *counters = &core->counters->core_errors;

	_ocf_core_stats_error_update(counters, dir);
}

void ocf_core_stats_cache_error_update(ocf_core_t core, uint8_t dir)
{
	struct ocf_counters_error *counters = &core->counters->cache_errors;

	_ocf_core_stats_error_update(counters, dir);
}

/********************************************************************
 * Function that resets stats, debug and breakdown counters.
 * If reset is set the following stats won't be reset:
 * - cache_occupancy
 * - queue_length
 * - debug_counters_read_reqs_issued_seq_hits
 * - debug_counters_read_reqs_issued_not_seq_hits
 * - debug_counters_read_reqs_issued_read_miss_schedule
 * - debug_counters_write_reqs_thread
 * - debug_counters_write_reqs_issued_only_hdd
 * - debug_counters_write_reqs_issued_both_devs
 *********************************************************************/
void ocf_core_stats_initialize(ocf_core_t core)
{
	struct ocf_counters_core *exp_obj_stats;
	int i;

	OCF_CHECK_NULL(core);

	exp_obj_stats = core->counters;

	ocf_stats_error_init(&exp_obj_stats->cache_errors);
	ocf_stats_error_init(&exp_obj_stats->core_errors);

	for (i = 0; i != OCF_USER_IO_CLASS_MAX; i++)
		ocf_stats_part_init(&exp_obj_stats->part_counters[i]);

#ifdef OCF_DEBUG_STATS
	ocf_stats_debug_init(&exp_obj_stats->debug_stats);
	ocf_volume_chkpts_stats_init(ocf_core_get_volume(core));
	ocf_volume_chkpts_stats_init(ocf_core_get_front_volume(core));
	ocf_volume_chkpts_stats_init(ocf_cache_get_volume(ocf_core_get_cache(core)));
#endif

	ocf_cache_feedback_counters_core_reset(core);
}

int ocf_core_stats_initialize_all(ocf_cache_t cache)
{
	ocf_core_id_t id;

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	for (id = 0; id < OCF_CORE_MAX; id++) {
		if (!env_bit_test(id, cache->conf_meta->valid_core_bitmap))
			continue;

		ocf_core_stats_initialize(&cache->core[id]);
	}

	return 0;
}

static void copy_req_stats(struct ocf_stats_req *dest,
		const struct ocf_counters_req *from)
{
	dest->deferred = env_atomic64_read(&from->deferred);
	dest->partial_miss = env_atomic64_read(&from->partial_miss);
	dest->full_miss = env_atomic64_read(&from->full_miss);
	dest->total = env_atomic64_read(&from->total);
	dest->pass_through = env_atomic64_read(&from->pass_through);
}

static void accum_req_stats(struct ocf_stats_req *dest,
		const struct ocf_counters_req *from)
{
	dest->deferred += env_atomic64_read(&from->deferred);
	dest->partial_miss += env_atomic64_read(&from->partial_miss);
	dest->full_miss += env_atomic64_read(&from->full_miss);
	dest->total += env_atomic64_read(&from->total);
	dest->pass_through += env_atomic64_read(&from->pass_through);
}

static void copy_block_stats(struct ocf_stats_block *dest,
		const struct ocf_counters_block *from)
{
	dest->read = env_atomic64_read(&from->read_bytes);
	dest->write = env_atomic64_read(&from->write_bytes);
}

static void accum_block_stats(struct ocf_stats_block *dest,
		const struct ocf_counters_block *from)
{
	dest->read += env_atomic64_read(&from->read_bytes);
	dest->write += env_atomic64_read(&from->write_bytes);
}

#if OCF_CCNT_ATOMIC
#define CCNT_PA_GET(pa_id, cnt)	env_atomic64_read(&from->alg_cnt[pa_id].cnt)
#define CCNT_G_GET(cnt)	        env_atomic64_read(&from->cnt)
#else
#define CCNT_PA_GET(pa_id, cnt)	(from->alg_cnt[pa_id].cnt)
#define CCNT_G_GET(cnt)	        (from->cnt)
#endif

static void copy_ocf_counters_cache_feedback(
		struct ocf_stats_cache_feedback *dest,
		const struct ocf_core_ocf_counters_cache_feedback *from)
{
	pf_algo_id_t pa_id;
	for_each_valid_pa_id(pa_id) {
		#define X(cnt) dest->alg_cnt[pa_id].cnt = CCNT_PA_GET(pa_id, cnt);
			OCF_CNT_CACHE_ALG
		#undef X
	}
	#define X(cnt) dest->cnt = CCNT_G_GET(cnt);
		OCF_CNT_CACHE_GLB
	#undef X
}

static void accum_ocf_counters_cache_feedback(
		struct ocf_stats_cache_feedback *dest,
		const struct ocf_core_ocf_counters_cache_feedback *from)
{
	pf_algo_id_t pa_id;
	for_each_valid_pa_id(pa_id) {
		#define X(cnt) dest->alg_cnt[pa_id].cnt += CCNT_PA_GET(pa_id, cnt);
			OCF_CNT_CACHE_ALG
		#undef X
	}
	#define X(cnt) dest->cnt += CCNT_G_GET(cnt);
		OCF_CNT_CACHE_GLB
	#undef X
}

static void copy_error_stats(struct ocf_stats_error *dest,
		const struct ocf_counters_error *from)
{
	dest->read = env_atomic_read(&from->read);
	dest->write = env_atomic_read(&from->write);
}

#ifdef OCF_DEBUG_STATS
static void copy_debug_stats_chkpts(chkpts_core_stats_t *dest, const chkpts_stats_t *src)
{
	dest->chkpts_cnt = env_atomic64_read(&src->chkpts_cnt);
	dest->chkpts_alloc_free = env_atomic64_read(&src->chkpts_alloc_free);
	dest->chkpts_alloc_sub = env_atomic64_read(&src->chkpts_alloc_sub);
	dest->chkpts_sub_comp = env_atomic64_read(&src->chkpts_sub_comp);
	dest->chkpts_comp_free = env_atomic64_read(&src->chkpts_comp_free);
	dest->chkpts_push_back_cnt = env_atomic64_read(&src->chkpts_push_back_cnt);
	dest->chkpts_push_back_pop = env_atomic64_read(&src->chkpts_push_back_pop);
	dest->chkpts_push_front_cnt = env_atomic64_read(&src->chkpts_push_front_cnt);
	dest->chkpts_push_front_pop = env_atomic64_read(&src->chkpts_push_front_pop);
}

static void copy_debug_stats(ocf_core_t core, struct ocf_stats_core_debug *dest,
		const struct ocf_counters_debug *from)
{
	ocf_volume_t vol;
	int i;

	for (i = 0; i < IO_PACKET_NO; i++) {
		dest->read_size[i] = env_atomic64_read(&from->read_size[i]);
		dest->write_size[i] = env_atomic64_read(&from->write_size[i]);
	}

	for (i = 0; i < IO_ALIGN_NO; i++) {
		dest->read_align[i] = env_atomic64_read(&from->read_align[i]);
		dest->write_align[i] = env_atomic64_read(&from->write_align[i]);
	}
	dest->read_slow_path = env_atomic64_read(&from->read_slow_path);
	dest->write_slow_path = env_atomic64_read(&from->write_slow_path);
	dest->concurrent_requests = env_atomic_read(&core->front_volume.refcnt.counter);

	vol = ocf_core_get_volume(core);
	copy_debug_stats_chkpts(&dest->chkpts_stats_core_rd, &vol->chkpts_stats_rd);
	copy_debug_stats_chkpts(&dest->chkpts_stats_core_wr, &vol->chkpts_stats_wr);
	vol = ocf_core_get_front_volume(core);
	copy_debug_stats_chkpts(&dest->chkpts_stats_ocf_rd, &vol->chkpts_stats_rd);
	copy_debug_stats_chkpts(&dest->chkpts_stats_ocf_wr, &vol->chkpts_stats_wr);
	vol = ocf_cache_get_volume(ocf_core_get_cache(core));
	copy_debug_stats_chkpts(&dest->chkpts_stats_cache_rd, &vol->chkpts_stats_rd);
	copy_debug_stats_chkpts(&dest->chkpts_stats_cache_wr, &vol->chkpts_stats_wr);
}
#endif

int ocf_core_io_class_get_stats(ocf_core_t core, ocf_part_id_t part_id,
		struct ocf_stats_io_class *stats)
{
	ocf_cache_t cache;
	struct ocf_counters_part *part_stat;
	pf_algo_id_t pa;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(stats);

	if (part_id > OCF_IO_CLASS_ID_MAX)
		return -OCF_ERR_INVAL;

	cache = ocf_core_get_cache(core);

	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	if (!ocf_user_part_is_valid(&cache->user_parts[part_id]))
		return -OCF_ERR_IO_CLASS_NOT_EXIST;

	part_stat = &core->counters->part_counters[part_id];

	stats->occupancy_clines = env_atomic_read(&core->runtime_meta->
			part_counters[part_id].cached_clines);
	stats->dirty_clines = env_atomic_read(&core->runtime_meta->
			part_counters[part_id].dirty_clines);

	stats->free_clines = 0;

	copy_req_stats(&stats->read_reqs, &part_stat->read_reqs);
	copy_req_stats(&stats->write_reqs, &part_stat->write_reqs);

	for_each_valid_pa_id(pa) {
		copy_req_stats(&stats->prefetch_reqs[pa],
			       &part_stat->prefetch_reqs[pa]);
		copy_block_stats(&stats->prefetch_cache_blocks[pa],
				 &part_stat->prefetch_cache_blocks[pa]);
		copy_block_stats(&stats->prefetch_core_blocks[pa],
				 &part_stat->prefetch_core_blocks[pa]);
	}

	copy_block_stats(&stats->blocks, &part_stat->blocks);
	copy_block_stats(&stats->cache_blocks, &part_stat->cache_blocks);
	copy_block_stats(&stats->core_blocks, &part_stat->core_blocks);
	copy_block_stats(&stats->pass_through_blocks, &part_stat->pass_through_blocks);

	copy_ocf_counters_cache_feedback(&stats->ocf_feedback, &part_stat->ocf_feedback);

	return 0;
}

int ocf_core_get_stats(ocf_core_t core, struct ocf_stats_core *stats)
{
	uint32_t i;
	struct ocf_counters_core *core_stats = NULL;
	struct ocf_counters_part *curr = NULL;
	ocf_cache_t cache;

	OCF_CHECK_NULL(core);

	if (!stats)
		return -OCF_ERR_INVAL;

	cache = ocf_core_get_cache(core);
	if (ocf_cache_is_standby(cache))
		return -OCF_ERR_CACHE_STANDBY;

	core_stats = core->counters;

	ENV_BUG_ON(env_memset(stats, sizeof(*stats), 0));

	copy_error_stats(&stats->core_errors,
			&core_stats->core_errors);
	copy_error_stats(&stats->cache_errors,
			&core_stats->cache_errors);

#ifdef OCF_DEBUG_STATS
	copy_debug_stats(core, &stats->debug_stat,
			&core_stats->debug_stats);
#endif

	for (i = 0; i != OCF_USER_IO_CLASS_MAX; i++) {
		pf_algo_id_t pa;
		curr = &core_stats->part_counters[i];

		accum_req_stats(&stats->read_reqs,
				&curr->read_reqs);
		accum_req_stats(&stats->write_reqs,
				&curr->write_reqs);

		for_each_valid_pa_id(pa) {
			accum_req_stats(&stats->prefetch_reqs[pa],
					&curr->prefetch_reqs[pa]);
			accum_block_stats(&stats->prefetch_cache_blocks[pa],
					  &curr->prefetch_cache_blocks[pa]);
			accum_block_stats(&stats->prefetch_core_blocks[pa],
					  &curr->prefetch_core_blocks[pa]);
		}

		accum_block_stats(&stats->core, &curr->blocks);
		accum_block_stats(&stats->core_volume, &curr->core_blocks);
		accum_block_stats(&stats->cache_volume, &curr->cache_blocks);
		accum_block_stats(&stats->pass_through_blocks, &curr->pass_through_blocks);

		stats->cache_occupancy += env_atomic_read(&core->runtime_meta->
				part_counters[i].cached_clines);
		stats->dirty += env_atomic_read(&core->runtime_meta->
				part_counters[i].dirty_clines);

		/* NOTE: does it make sense to accumulate over all io-classes? */
		accum_ocf_counters_cache_feedback(&stats->ocf_feedback, &curr->ocf_feedback);
	}

	return 0;
}

#ifdef OCF_DEBUG_STATS

#define IO_ALIGNMENT_SIZE (IO_ALIGN_NO)
#define IO_PACKET_SIZE ((IO_PACKET_NO) - 1)

static uint32_t io_alignment[IO_ALIGNMENT_SIZE] = {
	512, 1 * KiB, 2 * KiB, 4 * KiB
};

static int to_align_idx(uint64_t off)
{
	int i;

	for (i = IO_ALIGNMENT_SIZE - 1; i >= 0; i--) {
		if (off % io_alignment[i] == 0)
			return i;
	}

	return IO_ALIGNMENT_SIZE;
}

static uint32_t io_packet_size[IO_PACKET_SIZE] = {
	512, 1 * KiB, 2 * KiB, 4 * KiB, 8 * KiB,
	16 * KiB, 32 * KiB, 64 * KiB, 128 * KiB,
	256 * KiB, 512 * KiB
};


static int to_packet_idx(uint32_t len)
{
	int i = 0;

	for (i = 0; i < IO_PACKET_SIZE; i++) {
		if (len <= io_packet_size[i])
			return i;
	}

	return IO_PACKET_SIZE;
}

void ocf_core_update_stats(ocf_core_t core, ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	struct ocf_counters_debug *stats;
	int idx;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(io);

	stats = &core->counters->debug_stats;

	idx = to_packet_idx(req->bytes);
	if (req->rw == OCF_WRITE)
		env_atomic64_inc(&stats->write_size[idx]);
	else
		env_atomic64_inc(&stats->read_size[idx]);

	idx = to_align_idx(req->addr);
	if (req->rw == OCF_WRITE)
		env_atomic64_inc(&stats->write_align[idx]);
	else
		env_atomic64_inc(&stats->read_align[idx]);
}

void ocf_core_update_stats_slow_path(ocf_core_t core, ocf_io_t io)
{
	struct ocf_request *req = ocf_io_to_req(io);
	struct ocf_counters_debug *stats;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(io);

	stats = &core->counters->debug_stats;

	/* Increase slow-path counters */
	if (req->rw == OCF_WRITE)
		env_atomic64_inc(&stats->write_slow_path);
	else
		env_atomic64_inc(&stats->read_slow_path);
}

void ocf_stats_chkpts_update(ocf_io_t io, struct ocf_volume *volume)
{
	struct ocf_request *req = ocf_io_to_req(io);

	if (req->io.chkpts[DEBUG_CHKPT_ALLOC] &&
		req->io.chkpts[DEBUG_CHKPT_SUBMIT] &&
		req->io.chkpts[DEBUG_CHKPT_COMPLETE]) {
		chkpts_stats_t *cpstts;
		uint64_t ts = env_get_tick_count();

		cpstts = req->rw == OCF_READ ? &volume->chkpts_stats_rd : &volume->chkpts_stats_wr;
		env_atomic64_inc(&cpstts->chkpts_cnt);
		env_atomic64_add(ts - req->io.chkpts[DEBUG_CHKPT_ALLOC], &cpstts->chkpts_alloc_free);
		env_atomic64_add(req->io.chkpts[DEBUG_CHKPT_SUBMIT] - req->io.chkpts[DEBUG_CHKPT_ALLOC], &cpstts->chkpts_alloc_sub);
		env_atomic64_add(req->io.chkpts[DEBUG_CHKPT_COMPLETE] - req->io.chkpts[DEBUG_CHKPT_SUBMIT], &cpstts->chkpts_sub_comp);
		env_atomic64_add(ts - req->io.chkpts[DEBUG_CHKPT_COMPLETE], &cpstts->chkpts_comp_free);

		if (req->io.chkpts[DEBUG_CHKPT_POP]) {
			if (req->io.chkpts[DEBUG_CHKPT_PUSH_PRIO_LOW]) {
				env_atomic64_inc(&cpstts->chkpts_push_back_cnt);
				env_atomic64_add(req->io.chkpts[DEBUG_CHKPT_POP] - req->io.chkpts[DEBUG_CHKPT_PUSH_PRIO_LOW], &cpstts->chkpts_push_back_pop);
			} else if (req->io.chkpts[DEBUG_CHKPT_PUSH_PRIO_HIGH]) {
				env_atomic64_inc(&cpstts->chkpts_push_front_cnt);
				env_atomic64_add(req->io.chkpts[DEBUG_CHKPT_POP] - req->io.chkpts[DEBUG_CHKPT_PUSH_PRIO_HIGH], &cpstts->chkpts_push_front_pop);
			} else {
				ENV_WARN(true, "got push back/front (%"ENV_PRIu64"/%"ENV_PRIu64") timestamp but not pop\n",
					req->io.chkpts[DEBUG_CHKPT_PUSH_PRIO_LOW], req->io.chkpts[DEBUG_CHKPT_PUSH_PRIO_HIGH]);
			}
		}
	}
}
#else

void ocf_core_update_stats(ocf_core_t core, ocf_io_t io) {}
void ocf_core_update_stats_slow_path(ocf_core_t core, ocf_io_t io) {}

#endif
