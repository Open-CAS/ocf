/*
 * Copyright(c) 2021-2022 Intel Corporation
 * Copyright(c) 2022-2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf_concurrency.h"
#include "../metadata/metadata_internal.h"
#include "../metadata/metadata_io.h"
#include "../ocf_priv.h"
#include "../ocf_request.h"
#include "../utils/utils_alock.h"
#include "../utils/utils_cache_line.h"

struct pio_ctx {
	uint32_t segments_number;
	struct {
		enum ocf_metadata_segment_id id;
		uint64_t first_entry;
		uint64_t begin;
		uint64_t end;
	} segments[2];
};

#define OUT_OF_RANGE -1

#define get_pio_ctx(__alock) (void*)__alock + ocf_alock_obj_size();

static inline bool page_belongs_to_section(struct pio_ctx *pio_ctx,
		enum ocf_metadata_segment_id segment_id, uint32_t page)
{
	return page >= pio_ctx->segments[segment_id].begin &&
		page < pio_ctx->segments[segment_id].end;
}

static inline ocf_cache_line_t page_to_entry(struct pio_ctx *pio_ctx,
		enum ocf_metadata_segment_id segment_id, uint32_t page)
{
	uint32_t id_within_section;

	id_within_section = page - pio_ctx->segments[segment_id].begin;

	return pio_ctx->segments[segment_id].first_entry + id_within_section;
}

static ocf_cache_line_t ocf_pio_lock_get_entry(struct ocf_alock *alock,
		struct ocf_request *req, uint32_t id)
{
	uint32_t page;
	enum ocf_metadata_segment_id segment_id;
	struct pio_ctx *pio_ctx = get_pio_ctx(alock);
	page = req->core_line_first + id;

	for (segment_id = 0; segment_id < pio_ctx->segments_number; segment_id++) {
		if (page_belongs_to_section(pio_ctx, segment_id, page))
			return page_to_entry(pio_ctx, segment_id, page);
	}

	return OUT_OF_RANGE;
}

static int ocf_pio_lock_fast(struct ocf_alock *alock,
		struct ocf_request *req, int rw)
{
	ocf_cache_line_t entry;
	int ret = OCF_LOCK_ACQUIRED;
	int32_t i;
	ENV_BUG_ON(rw != OCF_WRITE);

	for (i = 0; i < req->core_line_count; i++) {
		entry = ocf_pio_lock_get_entry(alock, req, i);
		if (unlikely(entry == OUT_OF_RANGE))
			continue;

		ENV_BUG_ON(ocf_alock_is_index_locked(alock, req, i));

		if (ocf_alock_trylock_entry_wr(alock, entry)) {
			ocf_alock_mark_index_locked(alock, req, i, true);
		} else {
			ret = OCF_LOCK_NOT_ACQUIRED;
			break;
		}
	}

	if (ret != OCF_LOCK_NOT_ACQUIRED)
		return ret;

	/* Request is not locked, discard acquired locks */
	for (; i >= 0; i--) {
		entry = ocf_pio_lock_get_entry(alock, req, i);
		if (unlikely(entry == OUT_OF_RANGE))
			continue;

		if (ocf_alock_is_index_locked(alock, req, i)) {
			ocf_alock_unlock_one_wr(alock, entry);
			ocf_alock_mark_index_locked(alock, req, i, false);
		}
	}

	return ret;
}

static int ocf_pio_lock_slow(struct ocf_alock *alock,
		struct ocf_request *req, int rw, ocf_req_async_lock_cb cmpl)
{
	int32_t i;
	ocf_cache_line_t entry;
	int ret = OCF_LOCK_ACQUIRED;
	ENV_BUG_ON(rw != OCF_WRITE);

	for (i = 0; i < req->core_line_count; i++) {
		entry = ocf_pio_lock_get_entry(alock, req, i);
		if (unlikely(entry == OUT_OF_RANGE))
			continue;

		ENV_BUG_ON(ocf_alock_is_index_locked(alock, req, i));

		if (!ocf_alock_lock_one_wr(alock, entry, cmpl, req, i)) {
			ENV_BUG();
			/* lock not acquired and not added to wait list */
			ret = -OCF_ERR_NO_MEM;
			goto err;
		}
	}

	return ret;

err:
	for (; i >= 0; i--) {
		entry = ocf_pio_lock_get_entry(alock, req, i);
		if (unlikely(entry == OUT_OF_RANGE))
			continue;

		ocf_alock_waitlist_remove_entry(alock, req, entry, i, OCF_WRITE);
	}

	return ret;
}

static uint32_t ocf_pio_lock_get_entries_count(struct ocf_alock *alock,
		struct ocf_request *req)
{
	uint32_t i, count = 0;
	ocf_cache_line_t entry;

	for (i = 0; i < req->core_line_count; i++) {
		entry = ocf_pio_lock_get_entry(alock, req, i);
		if (unlikely(entry == OUT_OF_RANGE))
			continue;
		count++;
	}

	return count;
}

static struct ocf_alock_lock_cbs ocf_pio_conc_cbs = {
		.lock_entries_fast = ocf_pio_lock_fast,
		.lock_entries_slow = ocf_pio_lock_slow,
		.get_entries_count = ocf_pio_lock_get_entries_count
};

int ocf_pio_async_lock(struct ocf_alock *alock, struct ocf_request *req,
		ocf_req_async_lock_cb cmpl)
{
	return ocf_alock_lock_wr(alock, req, cmpl);
}

void ocf_pio_async_unlock(struct ocf_alock *alock, struct ocf_request *req)
{
	ocf_cache_line_t entry;
	int i;

	for (i = 0; i < req->core_line_count; i++) {
		if (!ocf_alock_is_index_locked(alock, req, i))
			continue;

		entry = ocf_pio_lock_get_entry(alock, req, i);
		if (unlikely(entry == OUT_OF_RANGE))
			continue;

		ocf_alock_unlock_one_wr(alock, entry);
		ocf_alock_mark_index_locked(alock, req, i, false);
	}

	req->alock_status = 0;
}

#define ALLOCATOR_NAME_FMT "ocf_%s_pio_conc"
#define ALLOCATOR_NAME_MAX (sizeof(ALLOCATOR_NAME_FMT) + OCF_CACHE_NAME_SIZE)

int ocf_pio_concurrency_init(struct ocf_alock **self, ocf_cache_t cache)
{
	struct ocf_metadata_ctrl *ctrl = cache->metadata.priv;
	struct ocf_alock *alock;
	struct pio_ctx *pio_ctx;
	size_t base_size = ocf_alock_obj_size();
	char name[ALLOCATOR_NAME_MAX];
	int ret;
	uint32_t pages_to_alloc = 0;
	enum ocf_metadata_segment_id update_segments[] = {
		metadata_segment_sb_config,
		metadata_segment_collision,
	};
	int i;

	ENV_BUILD_BUG_ON(
			ARRAY_SIZE(update_segments) > ARRAY_SIZE(pio_ctx->segments));

	ret = snprintf(name, sizeof(name), ALLOCATOR_NAME_FMT,
			ocf_cache_get_name(cache));
	if (ret < 0)
		return ret;
	if (ret >= ALLOCATOR_NAME_MAX)
		return -OCF_ERR_NO_MEM;

	alock = env_vzalloc(base_size + sizeof(struct pio_ctx));
	if (!alock)
		return -OCF_ERR_NO_MEM;

	pio_ctx = get_pio_ctx(alock);
	pio_ctx->segments_number = ARRAY_SIZE(update_segments);

	for (i = 0; i < pio_ctx->segments_number; i++) {
		struct ocf_metadata_raw *raw = &(ctrl->raw_desc[update_segments[i]]);
		pio_ctx->segments[i].first_entry = pages_to_alloc;
		pio_ctx->segments[i].id = update_segments[i];
		pio_ctx->segments[i].begin = raw->ssd_pages_offset;
		pio_ctx->segments[i].end = raw->ssd_pages_offset + raw->ssd_pages;

		pages_to_alloc += raw->ssd_pages;
	}

	ret = ocf_alock_init_inplace(alock, pages_to_alloc, name, &ocf_pio_conc_cbs, cache);
	if (ret) {
		env_vfree(alock);
		return ret;
	}

	*self = alock;
	return 0;
}

void ocf_pio_concurrency_deinit(struct ocf_alock **self)
{
	ocf_alock_deinit(self);
}
