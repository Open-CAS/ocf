/*
 * Copyright(c) 2012-2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"

#include "metadata.h"
#include "metadata_passive_update.h"
#include "metadata_collision.h"
#include "metadata_segment_id.h"
#include "metadata_internal.h"
#include "metadata_io.h"
#include "metadata_raw.h"
#include "metadata_segment.h"
#include "../concurrency/ocf_concurrency.h"
#include "../ocf_def_priv.h"
#include "../ocf_priv.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_io.h"
#include "../utils/utils_pipeline.h"
#include "../concurrency/ocf_pio_concurrency.h"
#include "../engine/engine_common.h"

#define MAX_PASSIVE_IO_SIZE (32*MiB)


static inline void _reset_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	/* The cacheline used to be dirty but it is not anymore so it needs to be
	   moved to a clean lru list */
	ocf_lru_clean_cline(cache, &cache->user_parts[PARTITION_DEFAULT].part,
			cline);

	metadata_init_status_bits(cache, cline);

	ocf_lru_rm_cline(cache, cline);
	ocf_metadata_set_partition_id(cache, cline, PARTITION_FREELIST);

	ocf_metadata_set_core_info(cache, cline, OCF_CORE_MAX, ULLONG_MAX);
}

static inline void remove_from_freelist(ocf_cache_t cache,
		ocf_cache_line_t cline)
{
	ocf_part_id_t lru_list;
	struct ocf_lru_list *list;

	lru_list = (cline % OCF_NUM_LRU_LISTS);
	list = ocf_lru_get_list(&cache->free, lru_list, true);

	OCF_METADATA_LRU_WR_LOCK(cline);
	ocf_lru_remove_locked(cache, list, cline);
	OCF_METADATA_LRU_WR_UNLOCK(cline);
}

static inline void remove_from_default(ocf_cache_t cache,
		ocf_cache_line_t cline)
{
	ocf_part_id_t part_id = PARTITION_DEFAULT;
	ocf_part_id_t lru_list;
	struct ocf_lru_list *list;

	lru_list = (cline % OCF_NUM_LRU_LISTS);
	list = ocf_lru_get_list(&cache->user_parts[part_id].part, lru_list, false);

	OCF_METADATA_LRU_WR_LOCK(cline);
	ocf_lru_remove_locked(cache, list, cline);
	OCF_METADATA_LRU_WR_UNLOCK(cline);

	env_atomic_dec(&cache->user_parts[part_id].part.runtime->curr_size);

}

static void handle_previously_invalid(ocf_cache_t cache,
		ocf_cache_line_t cline)
{
	ocf_core_id_t core_id;
	uint64_t core_line;
	uint32_t lock_idx = ocf_metadata_concurrency_next_idx(cache->mngt_queue);

	/* Pio lock provides exclusive access to the collision page thus either
	   mapping or status bits can't be changed by a concurrent thread */

	ocf_metadata_get_core_info(cache, cline, &core_id, &core_line);

	if (metadata_test_dirty(cache, cline) && core_id < OCF_CORE_MAX) {
		ENV_BUG_ON(!metadata_test_valid_any(cache, cline));
		/* Moving cline from the freelist to the default partitioin */
		remove_from_freelist(cache, cline);

		ocf_hb_cline_prot_lock_wr(&cache->metadata.lock, lock_idx, core_id,
				core_line);
		OCF_METADATA_LRU_WR_LOCK(cline);
		ocf_cline_rebuild_metadata(cache, core_id, core_line, cline);
		OCF_METADATA_LRU_WR_UNLOCK(cline);
		ocf_hb_cline_prot_unlock_wr(&cache->metadata.lock, lock_idx, core_id,
				core_line);
		ocf_cleaning_init_cache_block(cache, cline);
		ocf_cleaning_set_hot_cache_line(cache, cline);

	} else {
		/* Cline stays on the freelist*/

		/* To prevent random values in the metadata fill it with the defaults */
		metadata_init_status_bits(cache, cline);
		ocf_metadata_set_core_info(cache, cline, OCF_CORE_MAX, ULLONG_MAX);
	}
}

static void handle_previously_valid(ocf_cache_t cache,
		ocf_cache_line_t cline)
{
	ocf_core_id_t core_id;
	uint64_t core_line;
	uint32_t lock_idx = ocf_metadata_concurrency_next_idx(cache->mngt_queue);

	/* Pio lock provides exclusive access to the collision page thus either
	   mapping or status bits can't be changed by a concurrent thread */

	ocf_metadata_get_core_info(cache, cline, &core_id, &core_line);

	if (metadata_test_dirty(cache, cline) && core_id < OCF_CORE_MAX) {
		/* Cline stays on the default partition*/
		ENV_BUG_ON(!metadata_test_valid_any(cache, cline));

		remove_from_default(cache, cline);

		ocf_hb_cline_prot_lock_wr(&cache->metadata.lock, lock_idx, core_id,
				core_line);
		OCF_METADATA_LRU_WR_LOCK(cline);
		ocf_cline_rebuild_metadata(cache, core_id, core_line, cline);
		OCF_METADATA_LRU_WR_UNLOCK(cline);
		ocf_hb_cline_prot_unlock_wr(&cache->metadata.lock, lock_idx, core_id,
				core_line);
		ocf_cleaning_set_hot_cache_line(cache, cline);

	} else {
		/* Moving cline from the default partition to the freelist */
		ocf_cleaning_purge_cache_block(cache, cline);
		_reset_cline(cache, cline);
	}
}

static inline void update_list_segment(ocf_cache_t cache,
		ocf_cache_line_t start, ocf_cache_line_t count)
{
	ocf_cache_line_t cline, end;

	for (cline = start, end = start + count; cline < end; cline++) {
		ocf_part_id_t part_id;

		metadata_clear_dirty_if_invalid(cache, cline);
		metadata_clear_valid_if_clean(cache, cline);

		part_id = ocf_metadata_get_partition_id(cache, cline);
		switch (part_id) {
			case PARTITION_FREELIST:
				handle_previously_invalid(cache, cline);
				break;
			case PARTITION_DEFAULT:
				handle_previously_valid(cache, cline);
				break;
			default:
				ocf_cache_log(cache, log_crit, "Passive update: invalid "
						"part id for cacheline %u: %hu\n", cline, part_id);
				ENV_BUG();
				break;
		}
	}
}

static void _dec_core_stats(ocf_core_t core)
{
	ocf_part_id_t part = PARTITION_DEFAULT;

	env_atomic *core_occupancy_counter = &core->runtime_meta->cached_clines;
	env_atomic *part_occupancy_counter =
	    &core->runtime_meta->part_counters[part].cached_clines;

	env_atomic *core_dirty_counter = &core->runtime_meta->dirty_clines;
	env_atomic *part_dirty_counter =
	    &core->runtime_meta->part_counters[part].dirty_clines;

	ENV_BUG_ON(env_atomic_dec_return(core_occupancy_counter) < 0);
	ENV_BUG_ON(env_atomic_dec_return(part_occupancy_counter) < 0);

	ENV_BUG_ON(env_atomic_dec_return(core_dirty_counter) < 0);
	ENV_BUG_ON(env_atomic_dec_return(part_dirty_counter) < 0);
}

static void cleanup_old_mapping(ocf_cache_t cache, ocf_cache_line_t start,
		ocf_cache_line_t count)
{
	ocf_cache_line_t cline, end;
	uint32_t lock_idx = ocf_metadata_concurrency_next_idx(cache->mngt_queue);

	for (cline = start, end = start + count; cline < end; cline++) {
		ocf_core_id_t core_id;
		uint64_t core_line;
		ocf_core_t core;

		ocf_metadata_get_core_info(cache, cline, &core_id, &core_line);

		ENV_BUG_ON(core_id > OCF_CORE_ID_INVALID);

		core = ocf_cache_get_core(cache, core_id);
		if (!core)
			continue;

		ENV_BUG_ON(ocf_metadata_get_partition_id(cache, cline) !=
				PARTITION_DEFAULT);

		_dec_core_stats(core);

		ocf_hb_cline_prot_lock_wr(&cache->metadata.lock, lock_idx, core_id,
				core_line);
		ocf_metadata_remove_from_collision(cache, cline, PARTITION_DEFAULT);
		ocf_hb_cline_prot_unlock_wr(&cache->metadata.lock, lock_idx, core_id,
				core_line);
	}
}

static int passive_io_resume(struct ocf_request *req)
{
	ocf_cache_t cache = req->cache;
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_io *io = (struct ocf_io*) req->data;
	ctx_data_t *data = ocf_io_get_data(io);
	uint64_t io_start_page = BYTES_TO_PAGES(io->addr);
	uint64_t io_pages_count = BYTES_TO_PAGES(io->bytes);
	uint64_t io_end_page = io_start_page + io_pages_count - 1;
	ocf_end_io_t io_cmpl = req->master_io_req;
	ocf_cache_line_t cache_etries = ocf_metadata_collision_table_entries(cache);
	enum ocf_metadata_segment_id update_segments[] = {
		metadata_segment_sb_config,
		metadata_segment_collision,
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(update_segments); i++) {
		ocf_cache_line_t cache_line_count, cache_line_range_start;
		enum ocf_metadata_segment_id seg = update_segments[i];
		struct ocf_metadata_raw *raw = &(ctrl->raw_desc[seg]);
		uint64_t raw_start_page = raw->ssd_pages_offset;
		uint64_t raw_end_page = raw_start_page + raw->ssd_pages - 1;
		uint64_t overlap_start = OCF_MAX(io_start_page, raw_start_page);
		uint64_t overlap_end = OCF_MIN(io_end_page, raw_end_page);
		uint64_t overlap_start_data = overlap_start - io_start_page;
		uint64_t overlap_page;
		uint64_t overlap_count;

		if (overlap_start > overlap_end)
			continue;

		overlap_page = overlap_start - raw_start_page;
		overlap_count = overlap_end - overlap_start + 1;

		if (seg == metadata_segment_collision) {
			/* The range of cachelines with potentially updated collision
			   section */
			cache_line_range_start = overlap_page * raw->entries_in_page;
			cache_line_count = raw->entries_in_page * overlap_count;

			/* The last page of collision section may contain fewer entries than
			   entries_in_page */
			cache_line_count = OCF_MIN(cache_etries - cache_line_range_start,
					cache_line_count);

			/* The collision is not updated yet but the range of affected
			   cachelines is already known. Remove the old mapping related info
			   from the metadata */
			cleanup_old_mapping(cache, cache_line_range_start,
					cache_line_count);
		}

		ctx_data_seek(cache->owner, data, ctx_data_seek_begin,
				PAGES_TO_BYTES(overlap_start_data));
		ocf_metadata_raw_update(cache, raw, data, overlap_page, overlap_count);

		if (seg != metadata_segment_collision)
			continue;

		update_list_segment(cache, cache_line_range_start,
				cache_line_count);
	}

	ocf_pio_async_unlock(req->cache->standby.concurrency, req);
	io_cmpl(io, 0);
	env_allocator_del(cache->standby.allocator, req);
	return 0;
}

static struct ocf_io_if passive_io_restart_if = {
	.read = passive_io_resume,
	.write = passive_io_resume,
};

static void passive_io_page_lock_acquired(struct ocf_request *req)
{
	ocf_engine_push_req_front(req, true);
}

int ocf_metadata_passive_update(ocf_cache_t cache, struct ocf_io *io,
		ocf_end_io_t io_cmpl)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_request *req;
	uint64_t io_start_page = BYTES_TO_PAGES(io->addr);
	uint64_t io_end_page = io_start_page + BYTES_TO_PAGES(io->bytes);
	int lock = 0;

	if (io->dir == OCF_READ) {
		io_cmpl(io, 0);
		return 0;
	}

	if (io_start_page >= ctrl->count_pages) {
		io_cmpl(io, 0);
		return 0;
	}

	if (io->addr % PAGE_SIZE || io->bytes % PAGE_SIZE) {
		ocf_cache_log(cache, log_warn,
				"Metadata update not aligned to page size!\n");
		io_cmpl(io, -OCF_ERR_INVAL);
		return -OCF_ERR_INVAL;
	}

	if (io->bytes > MAX_PASSIVE_IO_SIZE) {
		//FIXME handle greater IOs
		ocf_cache_log(cache, log_warn,
				"IO size exceedes max supported size!\n");
		io_cmpl(io, -OCF_ERR_INVAL);
		return -OCF_ERR_INVAL;
	}

	req = (struct ocf_request*)env_allocator_new(cache->standby.allocator);
	if (!req) {
		io_cmpl(io, -OCF_ERR_NO_MEM);
		return -OCF_ERR_NO_MEM;
	}

	req->io_queue = io->io_queue;;
	req->info.internal = true;
	req->io_if = &passive_io_restart_if;
	req->rw = OCF_WRITE;
	req->data = io;
	req->master_io_req = io_cmpl;
	req->cache = cache;
	env_atomic_set(&req->lock_remaining, 0);

	req->core_line_first = io_start_page;
	req->core_line_count = io_end_page - io_start_page;
	req->alock_status = (uint8_t*)&req->map;

	lock = ocf_pio_async_lock(req->cache->standby.concurrency,
			req, passive_io_page_lock_acquired);
	if (lock < 0) {
		env_allocator_del(cache->standby.allocator, req);
		io_cmpl(io, lock);
		return lock;
	}

	if (lock == OCF_LOCK_ACQUIRED)
		passive_io_resume(req);

	return 0;
}

int ocf_metadata_passive_io_ctx_init(ocf_cache_t cache)
{
	char *name = "ocf_cache_pio";
	size_t element_size, header_size, size;

	header_size = sizeof(struct ocf_request);
	/* Only one bit per page is required. Since `alock_status` has `uint8_t*`
	   type, one entry can carry status for 8 pages. */
	element_size = OCF_DIV_ROUND_UP(BYTES_TO_PAGES(MAX_PASSIVE_IO_SIZE), 8);
	size = header_size + element_size;

	cache->standby.allocator = env_allocator_create(size, name, true);
	if (cache->standby.allocator == NULL)
		return -1;

	return 0;
}

void ocf_metadata_passive_io_ctx_deinit(ocf_cache_t cache)
{
	env_allocator_destroy(cache->standby.allocator);
}
