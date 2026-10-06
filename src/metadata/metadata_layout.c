/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "metadata_layout.h"
#include "metadata_bit.h"
#include "metadata_cleaning_policy.h"
#include "metadata_collision.h"
#include "metadata_core.h"
#include "metadata_lru.h"
#include "metadata_partition.h"
#include "metadata_superblock.h"

#define OCF_METADATA_LAYOUT_ITER_MAX 1000

ocf_cache_line_t ocf_metadata_segment_layout_entries(
		enum ocf_metadata_segment_id segment,
		ocf_cache_line_t cachelines)
{
	ENV_BUG_ON(segment >= metadata_segment_variable_size_start &&
			cachelines == 0);

	switch (segment) {
	case metadata_segment_collision:
	case metadata_segment_cleaning:
	case metadata_segment_lru:
	case metadata_segment_list_info:
		return cachelines;

	case metadata_segment_hash:
		return OCF_DIV_ROUND_UP(cachelines, 4);

	case metadata_segment_sb_config:
		return OCF_DIV_ROUND_UP(sizeof(struct ocf_superblock_config),
				PAGE_SIZE);

	case metadata_segment_sb_runtime:
		return OCF_DIV_ROUND_UP(sizeof(struct ocf_superblock_runtime),
				PAGE_SIZE);

	case metadata_segment_reserved:
		return 32;

	case metadata_segment_part_config:
		return OCF_USER_IO_CLASS_MAX + 1;

	case metadata_segment_part_runtime:
		return OCF_NUM_PARTITIONS;

	case metadata_segment_core_config:
		return OCF_CORE_NUM;

	case metadata_segment_core_runtime:
		return OCF_CORE_NUM;

	case metadata_segment_core_uuid:
		return OCF_CORE_NUM;

	default:
		break;
	}

	ENV_BUG();
	return 0;
}

uint32_t ocf_metadata_segment_layout_entry_size(
		enum ocf_metadata_segment_id segment,
		ocf_cache_line_size_t line_size)
{
	uint32_t size = 0;

	ENV_BUG_ON(segment >= metadata_segment_variable_size_start &&
			!line_size);

	switch (segment) {
	case metadata_segment_lru:
		size = sizeof(struct ocf_lru_meta);
		break;

	case metadata_segment_cleaning:
		size = sizeof(struct cleaning_policy_meta);
		break;

	case metadata_segment_collision:
		size = sizeof(struct ocf_metadata_map)
			+ ocf_metadata_status_sizeof(line_size);
		break;

	case metadata_segment_list_info:
		size = sizeof(struct ocf_metadata_list_info);
		break;

	case metadata_segment_sb_config:
		size = PAGE_SIZE;
		break;

	case metadata_segment_sb_runtime:
		size = PAGE_SIZE;
		break;

	case metadata_segment_reserved:
		size = PAGE_SIZE;
		break;

	case metadata_segment_part_config:
		size = sizeof(struct ocf_user_part_config);
		break;

	case metadata_segment_part_runtime:
		size = sizeof(struct ocf_part_runtime);
		break;

	case metadata_segment_hash:
		size = sizeof(struct ocf_hash_entry);
		break;

	case metadata_segment_core_config:
		size = sizeof(struct ocf_core_meta_config);
		break;

	case metadata_segment_core_runtime:
		size = sizeof(struct ocf_core_meta_runtime);
		break;

	case metadata_segment_core_uuid:
		size = sizeof(struct ocf_metadata_uuid);
		break;

	default:
		break;

	}

	ENV_BUG_ON(size > PAGE_SIZE);

	return size;
}

bool ocf_metadata_segment_layout_is_flapped(
		enum ocf_metadata_segment_id segment)
{
	switch (segment) {
	case metadata_segment_part_config:
	case metadata_segment_core_config:
	case metadata_segment_core_uuid:
		return true;

	case metadata_segment_sb_config:
	case metadata_segment_sb_runtime:
	case metadata_segment_reserved:
	case metadata_segment_part_runtime:
	case metadata_segment_core_runtime:
	case metadata_segment_cleaning:
	case metadata_segment_lru:
	case metadata_segment_collision:
	case metadata_segment_list_info:
	case metadata_segment_hash:
	default:
		return false;

	}
}

/*
 * Set up segment with given number of entries at given offset
 *
 * @return Number of pages occupied by segment on disk
 */
static uint32_t ocf_metadata_layout_setup_segment(
		struct ocf_metadata_layout *layout,
		enum ocf_metadata_segment_id id,
		ocf_cache_line_size_t line_size,
		ocf_cache_line_t entries, uint32_t offset)
{
	struct ocf_metadata_segment_layout *segment = &layout->segment[id];

	segment->disabled = false;
	segment->entry_size = ocf_metadata_segment_layout_entry_size(id,
			line_size);
	segment->entries_in_page = PAGE_SIZE / segment->entry_size;
	segment->flapping = ocf_metadata_segment_layout_is_flapped(id);
	segment->entries = entries;
	segment->offset = offset;
	segment->pages = OCF_DIV_ROUND_UP(segment->entries,
			segment->entries_in_page);

	if (!layout->on_disk)
		return 0;

	return ocf_metadata_segment_layout_pages(segment);
}

void ocf_metadata_layout_init_fixed_size(
		struct ocf_metadata_layout *layout, bool on_disk)
{
	uint32_t page = 0;
	uint32_t i;

	ENV_BUG_ON(env_memset(layout, sizeof(*layout), 0));

	layout->on_disk = on_disk;

	for (i = 0; i < metadata_segment_fixed_size_max; i++) {
		page += ocf_metadata_layout_setup_segment(layout, i, 0,
				ocf_metadata_segment_layout_entries(i, 0),
				page);
	}

	layout->pages_fixed = page;
}

void ocf_metadata_layout_set_cachelines(struct ocf_metadata_layout *layout,
		ocf_cache_line_size_t line_size, ocf_cache_line_t cachelines,
		bool cleaner_disabled)
{
	uint32_t page = 0;
	uint32_t i;

	layout->line_size = line_size;
	layout->cachelines = cachelines;

	for (i = metadata_segment_variable_size_start;
			i < metadata_segment_max; i++) {
		if (i == metadata_segment_cleaning && cleaner_disabled) {
			ENV_BUG_ON(env_memset(&layout->segment[i],
					sizeof(layout->segment[i]), 0));
			layout->segment[i].disabled = true;
			continue;
		}

		page += ocf_metadata_layout_setup_segment(layout, i, line_size,
				ocf_metadata_segment_layout_entries(i,
					cachelines),
				layout->pages_fixed + page);
	}

	layout->pages_variable = page;
}

/*
 * Accept inexact result only if at least 90% of device space is used
 */
static bool ocf_metadata_layout_accept_inexact(int64_t unused_lines,
		int64_t device_lines)
{
	int64_t utilization = 0;

	if (unused_lines < 0)
		return false;

	utilization = (device_lines - unused_lines) * 100 / device_lines;

	if (utilization < 90)
		return false;

	return true;
}

/*
 * Algorithm to calculate amount of cache lines taking into account required
 * space for metadata
 */
int ocf_metadata_layout_fit(struct ocf_metadata_layout *layout,
		ocf_cache_line_size_t line_size, uint64_t device_lines,
		bool cleaner_disabled, bool *inexact)
{
	int64_t i_diff = 0, diff_lines = 0, cache_lines = device_lines;
	int64_t lowest_diff;

	*inexact = false;

	lowest_diff = cache_lines;

	do {
		ocf_metadata_layout_set_cachelines(layout, line_size,
				cache_lines, cleaner_disabled);

		/*
		 * Check if max allowed iteration exceeded
		 */
		if (i_diff >= OCF_METADATA_LAYOUT_ITER_MAX) {
			/*
			 * Never should be here but try handle this exception
			 */
			*inexact = true;

			if (ocf_metadata_layout_accept_inexact(diff_lines,
					device_lines)) {
				break;
			}

			if (i_diff > (2 * OCF_METADATA_LAYOUT_ITER_MAX)) {
				/*
				 * We tried, but we fallen, have to return error
				 */
				return -OCF_ERR_INVAL;
			}
		}

		/* Calculate diff of cache lines */

		/* Cache size in bytes */
		diff_lines = device_lines * line_size;
		/* Sub metadata size which is in 4 kiB unit */
		diff_lines -= (int64_t)ocf_metadata_layout_pages(layout) *
				PAGE_SIZE;
		/* Convert back to cache lines */
		diff_lines /= line_size;
		/* Calculate difference */
		diff_lines -= cache_lines;

		if (diff_lines > 0) {
			if (diff_lines < lowest_diff)
				lowest_diff = diff_lines;
			else if (diff_lines == lowest_diff)
				break;
		}

		/* Update new value of cache lines */
		cache_lines += diff_lines;

		i_diff++;

	} while (diff_lines);

	if (device_lines < layout->cachelines)
		return -OCF_ERR_INVAL_CACHE_DEV;

	return 0;
}
