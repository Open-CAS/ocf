/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "metadata.h"
#include "metadata_hash.h"
#include "metadata_raw.h"
#include "metadata_io.h"
#include "metadata_status.h"
#include "../concurrency/ocf_concurrency.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_pipeline.h"
#include "../ocf_def_priv.h"

#define OCF_METADATA_HASH_DEBUG 0

#if 1 == OCF_METADATA_HASH_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Metadata][Hash] %s\n", __func__)

#define OCF_DEBUG_PARAM(cache, format, ...) \
	ocf_cache_log(cache, log_info, "[Metadata][Hash] %s - "format"\n", \
			__func__, ##__VA_ARGS__)
#else
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_PARAM(cache, format, ...)
#endif

#define METADATA_MEM_POOL(ctrl, section) ctrl->raw_desc[section].mem_pool

static void ocf_metadata_hash_init_iface(struct ocf_cache *cache,
		ocf_metadata_layout_t layout);

#define OCF_METADATA_HASH_DIFF_MAX 1000

enum {
	ocf_metadata_status_type_valid = 0,
	ocf_metadata_status_type_dirty,

	ocf_metadata_status_type_max
};

static inline size_t ocf_metadata_status_sizeof(
		const struct ocf_cache_line_settings *settings) {
	/* Number of bytes required to mark cache line status */
	size_t size = settings->sector_count / 8;

	/* Number of types of status (valid, dirty, etc...) */
	size *= ocf_metadata_status_type_max;

	/* At the end we have size */
	return size;
}

/*
 * Hash metadata control structure
 */
struct ocf_metadata_hash_ctrl {
	ocf_cache_line_t cachelines;
	ocf_cache_line_t start_page;
	ocf_cache_line_t count_pages;
	uint32_t device_lines;
	size_t mapping_size;
	struct ocf_metadata_raw raw_desc[metadata_segment_max];
};

/*
 * get entries for specified metadata hash type
 */
static ocf_cache_line_t ocf_metadata_hash_get_entires(
		enum ocf_metadata_segment type,
		ocf_cache_line_t cache_lines)
{
	ENV_BUG_ON(type >= metadata_segment_variable_size_start && cache_lines == 0);

	switch (type) {
	case metadata_segment_collision:
	case metadata_segment_cleaning:
	case metadata_segment_eviction:
	case metadata_segment_list_info:
		return cache_lines;

	case metadata_segment_hash:
		return OCF_DIV_ROUND_UP(cache_lines / 4, OCF_HASH_PRIME) *
				OCF_HASH_PRIME - 1;

	case metadata_segment_sb_config:
		return OCF_DIV_ROUND_UP(sizeof(struct ocf_superblock_config),
				PAGE_SIZE);

	case metadata_segment_sb_runtime:
		return OCF_DIV_ROUND_UP(sizeof(struct ocf_superblock_runtime),
				PAGE_SIZE);

	case metadata_segment_reserved:
		return 32;

	case metadata_segment_core_config:
		return OCF_CORE_MAX;

	case metadata_segment_core_runtime:
		return OCF_CORE_MAX;

	case metadata_segment_core_uuid:
		return OCF_CORE_MAX;

	default:
		break;
	}

	ENV_BUG();
	return 0;
}

/*
 * Get size of particular hash metadata type element
 */
static int64_t ocf_metadata_hash_get_element_size(
		enum ocf_metadata_segment type,
		const struct ocf_cache_line_settings *settings)
{
	int64_t size = 0;

	ENV_BUG_ON(type >= metadata_segment_variable_size_start && !settings);

	switch (type) {
	case metadata_segment_eviction:
		size = sizeof(union eviction_policy_meta);
		break;

	case metadata_segment_cleaning:
		size = sizeof(struct cleaning_policy_meta);
		break;

	case metadata_segment_collision:
		size = sizeof(struct ocf_metadata_map)
			+ ocf_metadata_status_sizeof(settings);
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

	case metadata_segment_hash:
		size = sizeof(ocf_cache_line_t);
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

/*
 * Metadata calculation exception handling.
 *
 * @param unused_lines - Unused pages
 * @param device_lines - SSD Cache device pages amount
 *
 * @return true - Accept unused sapce
 * @return false - unused space is not acceptable
 */
static bool ocf_metadata_hash_calculate_exception_hndl(ocf_cache_t cache,
		int64_t unused_lines, int64_t device_lines)
{
	static bool warn;
	int64_t utilization = 0;

	if (!warn) {
		ocf_cache_log(cache, log_warn,
				"Metadata size calculation problem\n");
		warn = true;
	}

	if (unused_lines < 0)
		return false;

	/*
	 * Accepted disk utilization is 90 % off SSD space
	 */
	utilization = (device_lines - unused_lines) * 100 / device_lines;

	if (utilization < 90)
		return false;

	return true;
}

/*
 * Algorithm to calculate amount of cache lines taking into account required
 * space for metadata
 */
static int ocf_metadata_hash_calculate_metadata_size(
		struct ocf_cache *cache,
		struct ocf_metadata_hash_ctrl *ctrl,
		const struct ocf_cache_line_settings *settings)
{
	int64_t i_diff = 0, diff_lines = 0, cache_lines = ctrl->device_lines;
	int64_t lowest_diff;
	ocf_cache_line_t count_pages;
	uint32_t i;

	OCF_DEBUG_PARAM(cache, "Cache lines = %lld", cache_lines);

	lowest_diff = cache_lines;

	do {
		count_pages = ctrl->count_pages;
		for (i = metadata_segment_variable_size_start;
				i < metadata_segment_max; i++) {
			struct ocf_metadata_raw *raw = &ctrl->raw_desc[i];

			/* Setup number of entries */
			raw->entries
				= ocf_metadata_hash_get_entires(i, cache_lines);

			/*
			 * Setup SSD location and size
			 */
			raw->ssd_pages_offset = count_pages;
			raw->ssd_pages = OCF_DIV_ROUND_UP(raw->entries,
					raw->entries_in_page);

			/* Update offset for next container */
			count_pages += ocf_metadata_raw_size_on_ssd(
					cache, raw);
		}

		/*
		 * Check if max allowed iteration exceeded
		 */
		if (i_diff >= OCF_METADATA_HASH_DIFF_MAX) {
			/*
			 * Never should be here but try handle this exception
			 */
			if (ocf_metadata_hash_calculate_exception_hndl(cache,
					diff_lines, ctrl->device_lines)) {
				break;
			}

			if (i_diff > (2 * OCF_METADATA_HASH_DIFF_MAX)) {
				/*
				 * We tried, but we fallen, have to return error
				 */
				ocf_cache_log(cache, log_err,
					"Metadata size calculation ERROR\n");
				return -1;
			}
		}

		/* Calculate diff of cache lines */

		/* Cache size in bytes */
		diff_lines = ctrl->device_lines * settings->size;
		/* Sub metadata size which is in 4 kiB unit */
		diff_lines -= count_pages * PAGE_SIZE;
		/* Convert back to cache lines */
		diff_lines /= settings->size;
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

		OCF_DEBUG_PARAM(cache, "Diff pages = %lld", diff_lines);
		OCF_DEBUG_PARAM(cache, "Cache lines = %lld", cache_lines);

		i_diff++;

	} while (diff_lines);

	ctrl->count_pages = count_pages;
	ctrl->cachelines = cache_lines;
	OCF_DEBUG_PARAM(cache, "Cache lines = %u", ctrl->cachelines);

	if (ctrl->device_lines < ctrl->cachelines)
		return -1;

	return 0;
}

static const char * const ocf_metadata_hash_raw_names[] = {
		[metadata_segment_sb_config]		= "Super block config",
		[metadata_segment_sb_runtime]		= "Super block runtime",
		[metadata_segment_reserved]		= "Reserved",
		[metadata_segment_cleaning]		= "Cleaning",
		[metadata_segment_eviction]		= "Eviction",
		[metadata_segment_collision]		= "Collision",
		[metadata_segment_list_info]		= "List info",
		[metadata_segment_hash]			= "Hash",
		[metadata_segment_core_config]		= "Core config",
		[metadata_segment_core_runtime]		= "Core runtime",
		[metadata_segment_core_uuid]		= "Core UUID",
};
#if 1 == OCF_METADATA_HASH_DEBUG
/*
 * Debug info functions prints metadata and raw containers information
 */
static void ocf_metadata_hash_raw_info(struct ocf_cache *cache,
		struct ocf_metadata_hash_ctrl *ctrl)
{
	uint64_t capacity = 0;
	uint64_t capacity_sum = 0;
	uint32_t i = 0;
	const char *unit;

	for (i = 0; i < metadata_segment_max; i++) {
		struct ocf_metadata_raw *raw = &(ctrl->raw_desc[i]);

		OCF_DEBUG_PARAM(cache, "Raw : name            = %s",
				ocf_metadata_hash_raw_names[i]);
		OCF_DEBUG_PARAM(cache, "    : metadata type   = %u", i);
		OCF_DEBUG_PARAM(cache, "    : raw type        = %u",
				raw->raw_type);
		OCF_DEBUG_PARAM(cache, "    : entry size      = %u",
				raw->entry_size);
		OCF_DEBUG_PARAM(cache, "    : entries         = %llu",
				raw->entries);
		OCF_DEBUG_PARAM(cache, "    : entries in page = %u",
				raw->entries_in_page);
		OCF_DEBUG_PARAM(cache, "    : page offset     = %llu",
				raw->ssd_pages_offset);
		OCF_DEBUG_PARAM(cache, "    : pages           = %llu",
				raw->ssd_pages);
	}

	/* Provide capacity info */
	for (i = 0; i < metadata_segment_max; i++) {
		capacity = ocf_metadata_raw_size_of(cache,
				&(ctrl->raw_desc[i]));

		capacity_sum += capacity;

		if (capacity / MiB) {
			capacity = capacity / MiB;
			unit = "MiB";
		} else {
			unit = "KiB";
			capacity = capacity / KiB;

		}

		OCF_DEBUG_PARAM(cache, "%s capacity %llu %s",
			ocf_metadata_hash_raw_names[i], capacity, unit);
	}
}
#else
#define ocf_metadata_hash_raw_info(cache, ctrl)
#endif

/*
 * Deinitialize hash metadata interface
 */
static void ocf_metadata_hash_deinit_variable_size(struct ocf_cache *cache)
{

	int result = 0;
	uint32_t i = 0;

	struct ocf_metadata_hash_ctrl *ctrl = (struct ocf_metadata_hash_ctrl *)
			cache->metadata.iface_priv;

	OCF_DEBUG_TRACE(cache);

	/*
	 * De initialize RAW types
	 */
	for (i = metadata_segment_variable_size_start;
			i < metadata_segment_max; i++) {
		result |= ocf_metadata_raw_deinit(cache,
				&(ctrl->raw_desc[i]));
	}
}

static inline void ocf_metadata_config_init(struct ocf_cache *cache,
		struct ocf_cache_line_settings *settings, size_t size)
{
	ENV_BUG_ON(!ocf_cache_line_size_is_valid(size));

	ENV_BUG_ON(env_memset(settings, sizeof(*settings), 0));

	settings->size = size;
	settings->sector_count = BYTES_TO_SECTORS(settings->size);
	settings->sector_start = 0;
	settings->sector_end = settings->sector_count - 1;

	OCF_DEBUG_PARAM(cache, "Cache line size = %lu, bits count = %llu, "
			"status size = %lu",
			settings->size, settings->sector_count,
			ocf_metadata_status_sizeof(settings));
}

static void ocf_metadata_hash_deinit(struct ocf_cache *cache)
{
	int result = 0;
	uint32_t i;

	struct ocf_metadata_hash_ctrl *ctrl = (struct ocf_metadata_hash_ctrl *)
			cache->metadata.iface_priv;

	for (i = 0; i < metadata_segment_fixed_size_max; i++) {
		result |= ocf_metadata_raw_deinit(cache,
				&(ctrl->raw_desc[i]));
	}

	env_vfree(ctrl);
	cache->metadata.iface_priv = NULL;

	if (result)
		ENV_BUG();
}

static int ocf_metadata_hash_init(struct ocf_cache *cache,
	ocf_cache_line_size_t cache_line_size)
{
	struct ocf_metadata_hash_ctrl *ctrl = NULL;
	struct ocf_cache_line_settings *settings =
		(struct ocf_cache_line_settings *)&cache->metadata.settings;
	uint32_t i = 0;
	uint32_t page = 0;
	int result = 0;

	OCF_DEBUG_TRACE(cache);

	ENV_WARN_ON(cache->metadata.iface_priv);

	ctrl = env_vzalloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	cache->metadata.iface_priv = ctrl;

	ocf_metadata_config_init(cache, settings, cache_line_size);

	/* Initial setup of RAW containers */
	for (i = 0; i < metadata_segment_fixed_size_max; i++) {
		struct ocf_metadata_raw *raw = &ctrl->raw_desc[i];

		raw->metadata_segment = i;

		/* Default type for metadata RAW container */
		raw->raw_type = metadata_raw_type_ram;

		if (cache->metadata.is_volatile) {
			raw->raw_type = metadata_raw_type_volatile;
		} else if (i == metadata_segment_core_uuid) {
			raw->raw_type = metadata_raw_type_dynamic;
		}

		/* Entry size configuration */
		raw->entry_size
			= ocf_metadata_hash_get_element_size(i, NULL);
		raw->entries_in_page = PAGE_SIZE / raw->entry_size;

		/* Setup number of entries */
		raw->entries = ocf_metadata_hash_get_entires(i, 0);

		/*
		 * Setup SSD location and size
		 */
		raw->ssd_pages_offset = page;
		raw->ssd_pages = OCF_DIV_ROUND_UP(raw->entries,
				raw->entries_in_page);

		/* Update offset for next container */
		page += ocf_metadata_raw_size_on_ssd(cache, raw);
	}

	ctrl->count_pages = page;

	for (i = 0; i < metadata_segment_fixed_size_max; i++) {
		result |= ocf_metadata_raw_init(cache, &(ctrl->raw_desc[i]));
		if (result)
			break;
	}

	if (result) {
		ocf_metadata_hash_deinit(cache);
	} else {
		cache->conf_meta = METADATA_MEM_POOL(ctrl,
				metadata_segment_sb_config);

		/* Set core metadata */
		cache->core_conf_meta = METADATA_MEM_POOL(ctrl,
				metadata_segment_core_config);

		cache->core_runtime_meta = METADATA_MEM_POOL(ctrl,
				metadata_segment_core_runtime);

		env_spinlock_init(&cache->metadata.lock.eviction);
		env_rwlock_init(&cache->metadata.lock.status);
		env_rwsem_init(&cache->metadata.lock.collision);
	}

	return result;
}



/*
 * Initialize hash metadata interface
 */
static int ocf_metadata_hash_init_variable_size(struct ocf_cache *cache,
		uint64_t device_size, ocf_cache_line_size_t cache_line_size,
		ocf_metadata_layout_t layout)
{
	int result = 0;
	uint32_t i = 0;
	ocf_cache_line_t line;
	struct ocf_metadata_hash_ctrl *ctrl = NULL;
	struct ocf_cache_line_settings *settings =
		(struct ocf_cache_line_settings *)&cache->metadata.settings;

	OCF_DEBUG_TRACE(cache);

	ENV_WARN_ON(!cache->metadata.iface_priv);

	ctrl = cache->metadata.iface_priv;

	ctrl->device_lines = device_size / cache_line_size;

	if (settings->size != cache_line_size)
		/* Re-initialize settings with different cache line size */
		ocf_metadata_config_init(cache, settings, cache_line_size);

	ctrl->mapping_size = ocf_metadata_status_sizeof(settings)
		+ sizeof(struct ocf_metadata_map);

	ocf_metadata_hash_init_iface(cache, layout);

	/* Initial setup of dynamic size RAW containers */
	for (i = metadata_segment_variable_size_start;
			i < metadata_segment_max; i++) {
		struct ocf_metadata_raw *raw = &ctrl->raw_desc[i];

		raw->metadata_segment = i;

		/* Default type for metadata RAW container */
		raw->raw_type = metadata_raw_type_ram;

		if (cache->device->init_mode == ocf_init_mode_metadata_volatile) {
			raw->raw_type = metadata_raw_type_volatile;
		} else if (i == metadata_segment_collision &&
				ocf_volume_is_atomic(&cache->device->volume)) {
			raw->raw_type = metadata_raw_type_atomic;
		}

		/* Entry size configuration */
		raw->entry_size
			= ocf_metadata_hash_get_element_size(i, settings);
		raw->entries_in_page = PAGE_SIZE / raw->entry_size;
	}

	if (0 != ocf_metadata_hash_calculate_metadata_size(cache, ctrl,
			settings)) {
		return -1;
	}

	OCF_DEBUG_PARAM(cache, "Metadata begin pages = %u", ctrl->start_page);
	OCF_DEBUG_PARAM(cache, "Metadata count pages = %u", ctrl->count_pages);
	OCF_DEBUG_PARAM(cache, "Metadata end pages = %u", ctrl->start_page
			+ ctrl->count_pages);

	/*
	 * Initialize all dynamic size  RAW types
	 */
	for (i = metadata_segment_variable_size_start;
			i < metadata_segment_max; i++) {
		result |= ocf_metadata_raw_init(cache, &(ctrl->raw_desc[i]));

		if (result)
			goto finalize;
	}

	for (i = 0; i < metadata_segment_max; i++) {
		ocf_cache_log(cache, log_info, "%s offset : %llu kiB\n",
				ocf_metadata_hash_raw_names[i],
				ctrl->raw_desc[i].ssd_pages_offset
				* PAGE_SIZE / KiB);
		if (i == metadata_segment_sb_config) {
			ocf_cache_log(cache, log_info, "%s size : %lu B\n",
				ocf_metadata_hash_raw_names[i],
				offsetof(struct ocf_superblock_config, checksum)
				+ sizeof(((struct ocf_superblock_config *)0)
						->checksum));
		} else if (i == metadata_segment_sb_runtime) {
			ocf_cache_log(cache, log_info, "%s size : %lu B\n",
				ocf_metadata_hash_raw_names[i],
				sizeof(struct ocf_superblock_runtime));
		} else {
			ocf_cache_log(cache, log_info, "%s size : %llu kiB\n",
					ocf_metadata_hash_raw_names[i],
					ctrl->raw_desc[i].ssd_pages
					* PAGE_SIZE / KiB);
		}
	}

finalize:
	if (result) {
		/*
		 * Hash De-Init also contains RAW deinitialization
		 */
		ocf_metadata_hash_deinit_variable_size(cache);
	} else {
		cache->device->runtime_meta = METADATA_MEM_POOL(ctrl,
				metadata_segment_sb_runtime);

		cache->device->collision_table_entries = ctrl->cachelines;

		cache->device->hash_table_entries =
				ctrl->raw_desc[metadata_segment_hash].entries;

		cache->device->metadata_offset = ctrl->count_pages * PAGE_SIZE;
		cache->device->metadata_offset_line = ctrl->count_pages;

		cache->conf_meta->cachelines = ctrl->cachelines;
		cache->conf_meta->line_size = cache_line_size;

		ocf_metadata_hash_raw_info(cache, ctrl);

		ocf_cache_log(cache, log_info, "Cache line size: %llu kiB\n",
				settings->size / KiB);

		ocf_cache_log(cache, log_info, "Metadata capacity: %llu MiB\n",
				(uint64_t)ocf_metadata_size_of(cache) / MiB);
	}

	/*
	 * Self test of metadata
	 */
	for (line = 0; line < cache->device->collision_table_entries; line++) {
		ocf_cache_line_t phy, lg;

		phy = ocf_metadata_map_lg2phy(cache, line);
		lg = ocf_metadata_map_phy2lg(cache, phy);

		if (line != lg) {
			result = -EINVAL;
			break;
		}
		env_cond_resched();
	}

	if (result == 0) {
		ocf_cache_log(cache, log_info,
				"OCF metadata self-test PASSED\n");
	} else {
		ocf_cache_log(cache, log_err,
				"OCF metadata self-test ERROR\n");
	}

	return result;
}

static inline void _ocf_init_collision_entry(struct ocf_cache *cache,
		ocf_cache_line_t idx, ocf_cache_line_t next,
		ocf_cache_line_t prev)
{
	ocf_cache_line_t invalid_idx = cache->device->collision_table_entries;
	ocf_part_id_t invalid_part_id = PARTITION_INVALID;

	ocf_metadata_set_partition_info(cache, idx,
			invalid_part_id, next, prev);
	ocf_metadata_set_collision_info(cache, idx, invalid_idx, invalid_idx);
	ocf_metadata_set_core_info(cache, idx,
			OCF_CORE_MAX, ULONG_MAX);
	metadata_init_status_bits(cache, idx);
}

/*
 * Default initialization of freelist partition
 */
static void ocf_metadata_hash_init_freelist_seq(struct ocf_cache *cache)
{
	uint32_t step = 0;
	unsigned int i = 0;
	ocf_cache_line_t collision_table_entries =
			cache->device->collision_table_entries;

	cache->device->freelist_part->head = 0;
	cache->device->freelist_part->curr_size = cache->device->collision_table_entries;

	/* hash_father is an index in hash_table and it's limited
	 * to the hash_table_entries
	 * hash_table_entries is invalid index here.
	 */
	_ocf_init_collision_entry(cache, i, 1, collision_table_entries);

	for (i = 1; i < collision_table_entries - 1; i++) {
		_ocf_init_collision_entry(cache, i, i + 1, i - 1);
		OCF_COND_RESCHED_DEFAULT(step);
	}

	cache->device->freelist_part->tail = i;
	_ocf_init_collision_entry(cache, i, collision_table_entries, i - 1);
}

/*
 * Modified initialization of freelist partition
 */
static void ocf_metadata_hash_init_freelist_striping(
		struct ocf_cache *cache)
{
	uint32_t step = 0;
	unsigned int i, j;
	ocf_cache_line_t prev, next;
	ocf_cache_line_t idx, last_page;
	ocf_cache_line_t collision_table_entries =
			cache->device->collision_table_entries;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;
	unsigned int entries_in_page =
		ctrl->raw_desc[metadata_segment_collision].entries_in_page;
	unsigned int pages =
		ctrl->raw_desc[metadata_segment_collision].ssd_pages;

	cache->device->freelist_part->head = 0;
	cache->device->freelist_part->curr_size = cache->device->collision_table_entries;

	/* Modified initialization procedure */
	prev = next = collision_table_entries;
	last_page = pages;

	for (i = 0; i < pages; i++) {
		idx = i * entries_in_page;
		for (j = 0; j < entries_in_page &&
				idx < collision_table_entries; j++) {
			next = idx + entries_in_page;

			if (next >= collision_table_entries)
				next = j + 1;

			_ocf_init_collision_entry(cache, idx, next, prev);

			if (idx >= entries_in_page - 1) {
				prev = idx - entries_in_page + 1;
			} else {
				prev = last_page * entries_in_page + j;
				if (prev >= collision_table_entries) {
					prev -= entries_in_page;
					last_page = pages - 1;
				}
			}

			OCF_COND_RESCHED_DEFAULT(step);
			idx++;
		}
	}

	if (collision_table_entries < entries_in_page) {
		idx = collision_table_entries - 1;
	} else {
		idx = pages * entries_in_page - 1;
		if (idx >= collision_table_entries)
			idx -= entries_in_page;

	}

	/* Terminate free list */
	cache->device->freelist_part->tail = idx;
	ocf_metadata_set_partition_next(cache, idx, collision_table_entries);
}


/*
 * Initialize hash table
 */
static void ocf_metadata_hash_init_hash_table(struct ocf_cache *cache)
{
	unsigned int i;
	unsigned int hash_table_entries = cache->device->hash_table_entries;
	ocf_cache_line_t invalid_idx = cache->device->collision_table_entries;

	/* Init hash table */
	for (i = 0; i < hash_table_entries; i++) {
		/* hash_table contains indexes from collision_table
		 * thus it shall be initialized in improper values
		 * from collision_table
		 **/
		ocf_metadata_set_hash(cache, i, invalid_idx);
	}

}

/*
 * Get count of pages that is dedicated for metadata
 */
static ocf_cache_line_t ocf_metadata_hash_pages(struct ocf_cache *cache)
{
	struct ocf_metadata_hash_ctrl *ctrl = NULL;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	return ctrl->count_pages;
}

/*
 * Get amount of cache lines
 */
static ocf_cache_line_t ocf_metadata_hash_cachelines(
		struct ocf_cache *cache)
{
	struct ocf_metadata_hash_ctrl *ctrl = NULL;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	return ctrl->cachelines;
}

static size_t ocf_metadata_hash_size_of(struct ocf_cache *cache)
{
	uint32_t i = 0;
	size_t size = 0;
	struct ocf_metadata_hash_ctrl *ctrl = NULL;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	/*
	 * Get size of all RAW metadata container
	 */
	for (i = 0; i < metadata_segment_max; i++) {
		size += ocf_metadata_raw_size_of(cache,
				&(ctrl->raw_desc[i]));
	}

	/* Get additional part of memory footprint */

	/* Cache concurrency mechnism */
	size += ocf_cache_concurrency_size_of(cache);

	return size;
}

/*******************************************************************************
 * Super Block
 ******************************************************************************/

struct ocf_metadata_hash_context {
	ocf_metadata_end_t cmpl;
	void *priv;
	ocf_pipeline_t pipeline;
	ocf_cache_t cache;
};

static void ocf_metadata_hash_generic_complete(void *priv, int error)
{
	struct ocf_metadata_hash_context *context = priv;

	if (error)
		ocf_pipeline_finish(context->pipeline, error);
	else
		ocf_pipeline_next(context->pipeline);
}

static void ocf_medatata_hash_load_segment(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	int segment = ocf_pipeline_arg_get_int(arg);
	struct ocf_metadata_hash_ctrl *ctrl;
	ocf_cache_t cache = context->cache;

	ctrl = (struct ocf_metadata_hash_ctrl *)cache->metadata.iface_priv;

	ocf_metadata_raw_load_all(cache, &ctrl->raw_desc[segment],
			ocf_metadata_hash_generic_complete, context);
}

static void ocf_medatata_hash_check_crc_sb_config(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	struct ocf_metadata_hash_ctrl *ctrl;
	struct ocf_superblock_config *sb_config;
	ocf_cache_t cache = context->cache;
	int segment = metadata_segment_sb_config;
	uint32_t crc;

	ctrl = (struct ocf_metadata_hash_ctrl *)cache->metadata.iface_priv;
	sb_config = METADATA_MEM_POOL(ctrl, metadata_segment_sb_config);

	crc = env_crc32(0, (void *)sb_config,
			offsetof(struct ocf_superblock_config, checksum));

	if (crc != sb_config->checksum[segment]) {
		/* Checksum does not match */
		ocf_cache_log(cache, log_err,
				"Loading %s ERROR, invalid checksum",
				ocf_metadata_hash_raw_names[segment]);
		ocf_pipeline_finish(pipeline, -OCF_ERR_INVAL);
		return;
	}

	ocf_pipeline_next(pipeline);
}

static void ocf_medatata_hash_check_crc(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	int segment = ocf_pipeline_arg_get_int(arg);
	struct ocf_metadata_hash_ctrl *ctrl;
	struct ocf_superblock_config *sb_config;
	ocf_cache_t cache = context->cache;
	uint32_t crc;

	ctrl = (struct ocf_metadata_hash_ctrl *)cache->metadata.iface_priv;
	sb_config = METADATA_MEM_POOL(ctrl, metadata_segment_sb_config);

	crc = ocf_metadata_raw_checksum(cache, &(ctrl->raw_desc[segment]));

	if (crc != sb_config->checksum[segment]) {
		/* Checksum does not match */
		ocf_cache_log(cache, log_err,
				"Loading %s ERROR, invalid checksum",
				ocf_metadata_hash_raw_names[segment]);
		ocf_pipeline_finish(pipeline, -OCF_ERR_INVAL);
		return;
	}

	ocf_pipeline_next(pipeline);
}

static void ocf_medatata_hash_load_superblock_post(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	struct ocf_metadata_hash_ctrl *ctrl;
	struct ocf_superblock_config *sb_config;
	ocf_cache_t cache = context->cache;
	struct ocf_metadata_uuid *muuid;
	struct ocf_volume_uuid uuid;
	uint32_t i;

	ctrl = (struct ocf_metadata_hash_ctrl *)cache->metadata.iface_priv;
	sb_config = METADATA_MEM_POOL(ctrl, metadata_segment_sb_config);

	for (i = 0; i < OCF_CORE_MAX; i++) {
		if (!cache->core_conf_meta[i].added)
			continue;

		muuid = ocf_metadata_get_core_uuid(cache, i);
		uuid.data = muuid->data;
		uuid.size = muuid->size;

		/* Initialize core volume */
		ocf_volume_init(&cache->core[i].volume,
				ocf_ctx_get_volume_type(cache->owner,
						cache->core_conf_meta[i].type),
				&uuid, false);
	}

	/* Restore all dynamics items */

	if (sb_config->core_count > OCF_CORE_MAX) {
		ocf_cache_log(cache, log_err,
			"Loading cache state ERROR, invalid cores count\n");
		ocf_pipeline_finish(pipeline, -OCF_ERR_INVAL);
		return;
	}

	if (sb_config->valid_parts_no > OCF_IO_CLASS_MAX) {
		ocf_cache_log(cache, log_err,
			"Loading cache state ERROR, invalid partition count\n");
		ocf_pipeline_finish(pipeline, -OCF_ERR_INVAL);
		return;
	}

	ocf_pipeline_next(pipeline);
}

static void ocf_metadata_hash_load_superblock_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_metadata_hash_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err, "Metadata read FAILURE\n");
		ocf_metadata_error(cache);
	}

	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_arg ocf_metadata_hash_load_sb_load_segment_args[] = {
	OCF_PL_ARG_INT(metadata_segment_sb_config),
	OCF_PL_ARG_INT(metadata_segment_sb_runtime),
	OCF_PL_ARG_INT(metadata_segment_core_config),
	OCF_PL_ARG_INT(metadata_segment_core_uuid),
	OCF_PL_ARG_TERMINATOR(),
};

struct ocf_pipeline_arg ocf_metadata_hash_load_sb_check_crc_args[] = {
	OCF_PL_ARG_INT(metadata_segment_sb_runtime),
	OCF_PL_ARG_INT(metadata_segment_core_config),
	OCF_PL_ARG_INT(metadata_segment_core_uuid),
	OCF_PL_ARG_TERMINATOR(),
};

struct ocf_pipeline_properties ocf_metadata_hash_load_sb_pipeline_props = {
	.priv_size = sizeof(struct ocf_metadata_hash_context),
	.finish = ocf_metadata_hash_load_superblock_finish,
	.steps = {
		OCF_PL_STEP_FOREACH(ocf_medatata_hash_load_segment,
				ocf_metadata_hash_load_sb_load_segment_args),
		OCF_PL_STEP(ocf_medatata_hash_check_crc_sb_config),
		OCF_PL_STEP_FOREACH(ocf_medatata_hash_check_crc,
				ocf_metadata_hash_load_sb_check_crc_args),
		OCF_PL_STEP(ocf_medatata_hash_load_superblock_post),
		OCF_PL_STEP_TERMINATOR(),
	},
};

/*
 * Super Block - Load, This function has to prevent to pointers overwrite
 */
static void ocf_metadata_hash_load_superblock(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_hash_context *context;
	ocf_pipeline_t pipeline;
	struct ocf_metadata_hash_ctrl *ctrl;
	struct ocf_superblock_config *sb_config;
	struct ocf_superblock_runtime *sb_runtime;
	int result;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;
	ENV_BUG_ON(!ctrl);

	sb_config = METADATA_MEM_POOL(ctrl, metadata_segment_sb_config);
	ENV_BUG_ON(!sb_config);

	sb_runtime = METADATA_MEM_POOL(ctrl, metadata_segment_sb_runtime);
	ENV_BUG_ON(!sb_runtime);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_metadata_hash_load_sb_pipeline_props);
	if (result) {
		cmpl(priv, result);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	ocf_pipeline_next(pipeline);
}

static void ocf_medatata_hash_flush_superblock_prepare(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	ocf_cache_t cache = context->cache;
	uint32_t i;

	/* Synchronize core objects types */
	for (i = 0; i < OCF_CORE_MAX; i++) {
		cache->core_conf_meta[i].type = ocf_ctx_get_volume_type_id(
				cache->owner, cache->core[i].volume.type);
	}

	ocf_pipeline_next(pipeline);
}

static void ocf_medatata_hash_calculate_crc_sb_config(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	struct ocf_metadata_hash_ctrl *ctrl;
	struct ocf_superblock_config *sb_config;
	ocf_cache_t cache = context->cache;

	ctrl = (struct ocf_metadata_hash_ctrl *)cache->metadata.iface_priv;
	sb_config = METADATA_MEM_POOL(ctrl, metadata_segment_sb_config);

	sb_config->checksum[metadata_segment_sb_config] = env_crc32(0,
			(void *)sb_config,
			offsetof(struct ocf_superblock_config, checksum));

	ocf_pipeline_next(pipeline);
}

static void ocf_medatata_hash_calculate_crc(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	int segment = ocf_pipeline_arg_get_int(arg);
	struct ocf_metadata_hash_ctrl *ctrl;
	struct ocf_superblock_config *sb_config;
	ocf_cache_t cache = context->cache;

	ctrl = (struct ocf_metadata_hash_ctrl *)cache->metadata.iface_priv;
	sb_config = METADATA_MEM_POOL(ctrl, metadata_segment_sb_config);

	sb_config->checksum[segment] = ocf_metadata_raw_checksum(cache,
			&(ctrl->raw_desc[segment]));

	ocf_pipeline_next(pipeline);
}

static void ocf_medatata_hash_flush_segment(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	int segment = ocf_pipeline_arg_get_int(arg);
	struct ocf_metadata_hash_ctrl *ctrl;
	ocf_cache_t cache = context->cache;

	ctrl = (struct ocf_metadata_hash_ctrl *)cache->metadata.iface_priv;
	
	ocf_metadata_raw_flush_all(cache, &ctrl->raw_desc[segment],
			ocf_metadata_hash_generic_complete, context);
}

static void ocf_metadata_hash_flush_superblock_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_metadata_hash_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error)
		ocf_metadata_error(cache);

	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_arg ocf_metadata_hash_flush_sb_calculate_crc_args[] = {
	OCF_PL_ARG_INT(metadata_segment_core_config),
	OCF_PL_ARG_INT(metadata_segment_core_uuid),
	OCF_PL_ARG_TERMINATOR(),
};

struct ocf_pipeline_arg ocf_metadata_hash_flush_sb_flush_segment_args[] = {
	OCF_PL_ARG_INT(metadata_segment_sb_config),
	OCF_PL_ARG_INT(metadata_segment_core_config),
	OCF_PL_ARG_INT(metadata_segment_core_uuid),
	OCF_PL_ARG_TERMINATOR(),
};

struct ocf_pipeline_properties ocf_metadata_hash_flush_sb_pipeline_props = {
	.priv_size = sizeof(struct ocf_metadata_hash_context),
	.finish = ocf_metadata_hash_flush_superblock_finish,
	.steps = {
		OCF_PL_STEP(ocf_medatata_hash_flush_superblock_prepare),
		OCF_PL_STEP(ocf_medatata_hash_calculate_crc_sb_config),
		OCF_PL_STEP_FOREACH(ocf_medatata_hash_calculate_crc,
				ocf_metadata_hash_flush_sb_calculate_crc_args),
		OCF_PL_STEP_FOREACH(ocf_medatata_hash_flush_segment,
				ocf_metadata_hash_flush_sb_flush_segment_args),
		OCF_PL_STEP_TERMINATOR(),
	},
};

/*
 * Super Block - FLUSH
 */
static void ocf_metadata_hash_flush_superblock(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_hash_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_DEBUG_TRACE(cache);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_metadata_hash_flush_sb_pipeline_props);
	if (result) {
		cmpl(priv, result);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	ocf_pipeline_next(pipeline);
}

/**
 * @brief Super Block - Set Shutdown Status
 *
 * to get shutdown status, one needs to call ocf_metadata_load_properties.
 * @param shutdown_status - status to be assigned to cache.
 *
 * @return Operation status (0 success, otherwise error)
 */
static void ocf_metadata_hash_set_shutdown_status(ocf_cache_t cache,
		enum ocf_metadata_shutdown_status shutdown_status,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_hash_ctrl *ctrl;
	struct ocf_superblock_config *superblock;

	OCF_DEBUG_TRACE(cache);

	/*
	 * Get metadata hash service control structure
	 */
	ctrl = (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	/*
	 * Get super block
	 */
	superblock = METADATA_MEM_POOL(ctrl, metadata_segment_sb_config);

	/* Set shutdown status */
	superblock->clean_shutdown = shutdown_status;
	superblock->magic_number = CACHE_MAGIC_NUMBER;

	/* Flush superblock */
	ocf_metadata_hash_flush_superblock(cache, cmpl, priv);
}

/*******************************************************************************
 * RESERVED AREA
 ******************************************************************************/

static uint64_t ocf_metadata_hash_get_reserved_lba(
		struct ocf_cache *cache)
{
	struct ocf_metadata_hash_ctrl *ctrl;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;
	return ctrl->raw_desc[metadata_segment_reserved].ssd_pages_offset *
			PAGE_SIZE;
}

/*******************************************************************************
 * FLUSH AND LOAD ALL
 ******************************************************************************/

static void ocf_medatata_hash_flush_all_set_status_complete(
		void *priv, int error)
{
	struct ocf_metadata_hash_context *context = priv;

	if (error) {
		ocf_pipeline_finish(context->pipeline, error);
		return;
	}

	ocf_pipeline_next(context->pipeline);
}

static void ocf_medatata_hash_flush_all_set_status(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	ocf_cache_t cache = context->cache;
	enum ocf_metadata_shutdown_status shutdown_status =
			ocf_pipeline_arg_get_int(arg);

	ocf_metadata_hash_set_shutdown_status(cache, shutdown_status,
			ocf_medatata_hash_flush_all_set_status_complete,
			context);
}

static void ocf_metadata_hash_flush_all_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_metadata_hash_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err, "Metadata Flush ERROR\n");
		ocf_metadata_error(cache);
		goto out;
	}

	ocf_cache_log(cache, log_info, "Done saving cache state!\n");

out:
	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_arg ocf_metadata_hash_flush_all_args[] = {
	OCF_PL_ARG_INT(metadata_segment_sb_runtime),
	OCF_PL_ARG_INT(metadata_segment_core_runtime),
	OCF_PL_ARG_INT(metadata_segment_cleaning),
	OCF_PL_ARG_INT(metadata_segment_eviction),
	OCF_PL_ARG_INT(metadata_segment_collision),
	OCF_PL_ARG_INT(metadata_segment_list_info),
	OCF_PL_ARG_INT(metadata_segment_hash),
	OCF_PL_ARG_TERMINATOR(),
};

struct ocf_pipeline_properties ocf_metadata_hash_flush_all_pipeline_props = {
	.priv_size = sizeof(struct ocf_metadata_hash_context),
	.finish = ocf_metadata_hash_flush_all_finish,
	.steps = {
		OCF_PL_STEP_ARG_INT(ocf_medatata_hash_flush_all_set_status,
				ocf_metadata_dirty_shutdown),
		OCF_PL_STEP_FOREACH(ocf_medatata_hash_flush_segment,
				ocf_metadata_hash_flush_all_args),
		OCF_PL_STEP_FOREACH(ocf_medatata_hash_calculate_crc,
				ocf_metadata_hash_flush_all_args),
		OCF_PL_STEP_ARG_INT(ocf_medatata_hash_flush_all_set_status,
				ocf_metadata_clean_shutdown),
		OCF_PL_STEP_TERMINATOR(),
	},
};

/*
 * Flush all metadata
 */
static void ocf_metadata_hash_flush_all(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_hash_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_DEBUG_TRACE(cache);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_metadata_hash_flush_all_pipeline_props);
	if (result) {
		cmpl(priv, result);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	ocf_pipeline_next(pipeline);
}

/*
 * Flush specified cache line
 */
static void ocf_metadata_hash_flush_mark(struct ocf_cache *cache,
		struct ocf_request *req, uint32_t map_idx, int to_state,
		uint8_t start, uint8_t stop)
{
	struct ocf_metadata_hash_ctrl *ctrl = NULL;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	/*
	 * Mark all required metadata elements to make given metadata cache
	 * line persistent in case of recovery
	 */

	/* Collision table to get mapping cache line to HDD sector*/
	ocf_metadata_raw_flush_mark(cache,
			&(ctrl->raw_desc[metadata_segment_collision]),
			req, map_idx, to_state, start, stop);
}

/*
 * Flush specified cache lines asynchronously
 */
static void ocf_metadata_hash_flush_do_asynch(struct ocf_cache *cache,
		struct ocf_request *req, ocf_req_end_t complete)
{
	int result = 0;
	struct ocf_metadata_hash_ctrl *ctrl = NULL;

	OCF_DEBUG_TRACE(cache);

	ctrl = (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	/*
	 * Flush all required metadata elements to make given metadata cache
	 * line persistent in case of recovery
	 */

	env_atomic_inc(&req->req_remaining); /* Core device IO */

	result |= ocf_metadata_raw_flush_do_asynch(cache, req,
			&(ctrl->raw_desc[metadata_segment_collision]),
			complete);

	if (result) {
		ocf_metadata_error(cache);
		ocf_cache_log(cache, log_err, "Metadata Flush ERROR\n");
	}
}

static void ocf_metadata_hash_load_all_finish(ocf_pipeline_t pipeline,
		void *priv, int error)
{
	struct ocf_metadata_hash_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err, "Metadata read FAILURE\n");
		ocf_metadata_error(cache);
		goto out;
	}

	ocf_cache_log(cache, log_info, "Done loading cache state\n");

out:
	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_arg ocf_metadata_hash_load_all_args[] = {
	OCF_PL_ARG_INT(metadata_segment_core_runtime),
	OCF_PL_ARG_INT(metadata_segment_cleaning),
	OCF_PL_ARG_INT(metadata_segment_eviction),
	OCF_PL_ARG_INT(metadata_segment_collision),
	OCF_PL_ARG_INT(metadata_segment_list_info),
	OCF_PL_ARG_INT(metadata_segment_hash),
	OCF_PL_ARG_TERMINATOR(),
};

struct ocf_pipeline_properties ocf_metadata_hash_load_all_pipeline_props = {
	.priv_size = sizeof(struct ocf_metadata_hash_context),
	.finish = ocf_metadata_hash_load_all_finish,
	.steps = {
		OCF_PL_STEP_FOREACH(ocf_medatata_hash_load_segment,
				ocf_metadata_hash_load_all_args),
		OCF_PL_STEP_FOREACH(ocf_medatata_hash_check_crc,
				ocf_metadata_hash_load_all_args),
		OCF_PL_STEP_TERMINATOR(),
	},
};

/*
 * Load all metadata
 */
static void ocf_metadata_hash_load_all(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_hash_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_DEBUG_TRACE(cache);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_metadata_hash_load_all_pipeline_props);
	if (result) {
		cmpl(priv, result);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	ocf_pipeline_next(pipeline);
}

static void _recovery_rebuild_cline_metadata(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t core_line,
		ocf_cache_line_t cache_line)
{
	ocf_part_id_t part_id;
	ocf_cache_line_t hash_index;

	part_id = PARTITION_DEFAULT;

	ocf_metadata_remove_from_free_list(cache, cache_line);

	ocf_metadata_add_to_partition(cache, part_id, cache_line);

	hash_index = ocf_metadata_hash_func(cache, core_line, core_id);
	ocf_metadata_add_to_collision(cache, core_id, core_line, hash_index,
			cache_line);

	ocf_eviction_init_cache_line(cache, cache_line, part_id);

	ocf_eviction_set_hot_cache_line(cache, cache_line);

	env_atomic_inc(&cache->core_runtime_meta[core_id].cached_clines);
	env_atomic_inc(&cache->core_runtime_meta[core_id].
			part_counters[part_id].cached_clines);

	if (metadata_test_dirty(cache, cache_line)) {
		env_atomic_inc(&cache->core_runtime_meta[core_id].
				dirty_clines);
		env_atomic_inc(&cache->core_runtime_meta[core_id].
				part_counters[part_id].dirty_clines);
		env_atomic64_cmpxchg(&cache->core_runtime_meta[core_id].
				dirty_since, 0, env_get_tick_count());
	}
}

static void _recovery_invalidate_clean_sec(struct ocf_cache *cache,
		ocf_cache_line_t cline)
{
	uint8_t i;

	for (i = ocf_line_start_sector(cache);
	     i <= ocf_line_end_sector(cache); i++) {
		if (!metadata_test_dirty_one(cache, cline, i)) {
			/* Invalidate clear sectors */
			metadata_clear_valid_sec_one(cache, cline, i);
		}
	}
}

static void _recovery_reset_cline_metadata(struct ocf_cache *cache,
		ocf_cache_line_t cline)
{
	ocf_cleaning_t clean_policy_type;

	ocf_metadata_set_core_info(cache, cline, OCF_CORE_MAX, ULLONG_MAX);

	metadata_clear_valid(cache, cline);

	clean_policy_type = cache->conf_meta->cleaning_policy_type;

	ENV_BUG_ON(clean_policy_type >= ocf_cleaning_max);

	if (cleaning_policy_ops[clean_policy_type].init_cache_block != NULL)
		cleaning_policy_ops[clean_policy_type].
			init_cache_block(cache, cline);
}

static void _recovery_rebuild_metadata(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	bool dirty_only = ocf_pipeline_arg_get_int(arg);
	ocf_cache_t cache = context->cache;
	ocf_cache_line_t cline;
	ocf_core_id_t core_id;
	uint64_t core_line;
	unsigned char step = 0;

	OCF_METADATA_LOCK_WR();

	for (cline = 0; cline < cache->device->collision_table_entries; cline++) {
		ocf_metadata_get_core_info(cache, cline, &core_id, &core_line);
		if (core_id != OCF_CORE_MAX &&
				(!dirty_only || metadata_test_dirty(cache,
						cline))) {
			/* Rebuild metadata for mapped cache line */
			_recovery_rebuild_cline_metadata(cache, core_id,
					core_line, cline);
			if (dirty_only)
				_recovery_invalidate_clean_sec(cache, cline);
		} else {
			/* Reset metadata for not mapped or clean cache line */
			_recovery_reset_cline_metadata(cache, cline);
		}

		OCF_COND_RESCHED(step, 128);
	}

	OCF_METADATA_UNLOCK_WR();

	ocf_pipeline_next(pipeline);
}

static void ocf_metadata_hash_load_recovery_legacy_finish(
		ocf_pipeline_t pipeline, void *priv, int error)
{
	struct ocf_metadata_hash_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"Metadata read for recovery FAILURE\n");
		ocf_metadata_error(cache);
		goto out;
	}

	ocf_cache_log(cache, log_info, "Done loading cache state\n");

out:
	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_properties
ocf_metadata_hash_load_recovery_legacy_pl_props = {
	.priv_size = sizeof(struct ocf_metadata_hash_context),
	.finish = ocf_metadata_hash_load_recovery_legacy_finish,
	.steps = {
		OCF_PL_STEP_ARG_INT(ocf_medatata_hash_load_segment,
				metadata_segment_collision),
		OCF_PL_STEP_ARG_INT(_recovery_rebuild_metadata, true),
		OCF_PL_STEP_TERMINATOR(),
	},
};

static void _ocf_metadata_hash_load_recovery_legacy(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_hash_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_DEBUG_TRACE(cache);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_metadata_hash_load_recovery_legacy_pl_props);
	if (result) {
		cmpl(priv, result);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	ocf_pipeline_next(pipeline);
}

static ocf_core_id_t _ocf_metadata_hash_find_core_by_seq(
		struct ocf_cache *cache, ocf_seq_no_t seq_no)
{
	ocf_core_id_t i;

	if (seq_no == OCF_SEQ_NO_INVALID)
		return OCF_CORE_ID_INVALID;

	for (i = OCF_CORE_ID_MIN; i <= OCF_CORE_ID_MAX; i++)
		if (cache->core_conf_meta[i].seq_no == seq_no)
			break;

	return i;
}

static void ocf_metadata_hash_load_atomic_metadata_complete(
		ocf_cache_t cache, void *priv, int error)
{
	struct ocf_metadata_hash_context *context = priv;

	if (error) {
		ocf_pipeline_finish(context->pipeline, error);
		return;
	}

	ocf_pipeline_next(context->pipeline);
}

static int ocf_metadata_hash_load_atomic_metadata_drain(void *priv,
		uint64_t sector_addr, uint32_t sector_no, ctx_data_t *data)
{
	struct ocf_metadata_hash_context *context = priv;
	ocf_cache_t cache = context->cache;
	struct ocf_atomic_metadata meta;
	ocf_cache_line_t line = 0;
	uint8_t pos = 0;
	ocf_seq_no_t core_seq_no = OCF_SEQ_NO_INVALID;
	ocf_core_id_t core_id = OCF_CORE_ID_INVALID;
	uint64_t core_line = 0;
	bool core_line_ok = false;
	uint32_t i;

	for (i = 0; i < sector_no; i++) {
		ctx_data_rd_check(cache->owner, &meta, data, sizeof(meta));

		line = (sector_addr + i) / ocf_line_sectors(cache);
		line = ocf_metadata_map_phy2lg(cache, line);
		pos = (sector_addr + i) % ocf_line_sectors(cache);
		core_seq_no = meta.core_seq_no;
		core_line = meta.core_line;

		/* Look for core with sequence number same as cache line */
		core_id = _ocf_metadata_hash_find_core_by_seq(
				cache, core_seq_no);

		if (pos == 0)
			core_line_ok = false;

		if (meta.valid && core_id != OCF_CORE_ID_INVALID) {
			if (!core_line_ok) {
				ocf_metadata_set_core_info(cache, line,
							core_id, core_line);
				core_line_ok = true;
			}

			metadata_set_valid_sec_one(cache, line, pos);
			meta.dirty ?
				metadata_set_dirty_sec_one(cache, line, pos) :
				metadata_clear_dirty_sec_one(cache, line, pos);
		}
	}

	return 0;
}

static void ocf_medatata_hash_load_atomic_metadata(
		ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_hash_context *context = priv;
	ocf_cache_t cache = context->cache;
	int result;

	result = metadata_io_read_i_atomic(cache, cache->mngt_queue,
			context, ocf_metadata_hash_load_atomic_metadata_drain,
			ocf_metadata_hash_load_atomic_metadata_complete);
	if (result) {
		ocf_metadata_error(cache);
		ocf_cache_log(cache, log_err,
				"Metadata read for recovery FAILURE\n");
		ocf_pipeline_finish(pipeline, result);
	}
}

static void ocf_metadata_hash_load_recovery_atomic_finish(
		ocf_pipeline_t pipeline, void *priv, int error)
{
	struct ocf_metadata_hash_context *context = priv;
	ocf_cache_t cache = context->cache;

	if (error) {
		ocf_cache_log(cache, log_err,
				"Metadata read for recovery FAILURE\n");
		ocf_metadata_error(cache);
	}

	context->cmpl(context->priv, error);
	ocf_pipeline_destroy(pipeline);
}

struct ocf_pipeline_properties
ocf_metadata_hash_load_recovery_atomic_pl_props = {
	.priv_size = sizeof(struct ocf_metadata_hash_context),
	.finish = ocf_metadata_hash_load_recovery_atomic_finish,
	.steps = {
		OCF_PL_STEP(ocf_medatata_hash_load_atomic_metadata),
		OCF_PL_STEP_ARG_INT(_recovery_rebuild_metadata, false),
		OCF_PL_STEP_TERMINATOR(),
	},
};

/*
 * RAM Implementation - Load all metadata elements from SSD
 */
static void _ocf_metadata_hash_load_recovery_atomic(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	struct ocf_metadata_hash_context *context;
	ocf_pipeline_t pipeline;
	int result;

	OCF_DEBUG_TRACE(cache);

	result = ocf_pipeline_create(&pipeline, cache,
			&ocf_metadata_hash_load_recovery_atomic_pl_props);
	if (result) {
		cmpl(priv, result);
		return;
	}

	context = ocf_pipeline_get_priv(pipeline);

	context->cmpl = cmpl;
	context->priv = priv;
	context->pipeline = pipeline;
	context->cache = cache;

	ocf_pipeline_next(pipeline);
}

/*
 * Load for recovery - Load only data that is required for recovery procedure
 */
static void ocf_metadata_hash_load_recovery(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv)
{
	OCF_DEBUG_TRACE(cache);

	if (ocf_volume_is_atomic(&cache->device->volume))
		_ocf_metadata_hash_load_recovery_atomic(cache, cmpl, priv);
	else
		_ocf_metadata_hash_load_recovery_legacy(cache, cmpl, priv);
}

/*******************************************************************************
 * Core Info
 ******************************************************************************/
static void ocf_metadata_hash_get_core_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_core_id_t *core_id,
		uint64_t *core_sector)
{
	const struct ocf_metadata_map *collision;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	collision = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_collision]), line,
			ctrl->mapping_size);
	if (collision) {
		if (core_id)
			*core_id = collision->core_id;
		if (core_sector)
			*core_sector = collision->core_line;
	} else {
		ocf_metadata_error(cache);

		if (core_id)
			*core_id = OCF_CORE_MAX;
		if (core_sector)
			*core_sector = ULLONG_MAX;
	}
}

static void ocf_metadata_hash_set_core_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_core_id_t core_id,
		uint64_t core_sector)
{
	struct ocf_metadata_map *collisioin;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	collisioin = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_collision]), line,
			ctrl->mapping_size);

	if (collisioin) {
		collisioin->core_id = core_id;
		collisioin->core_line = core_sector;
	} else {
		ocf_metadata_error(cache);
	}
}

static ocf_core_id_t ocf_metadata_hash_get_core_id(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	const struct ocf_metadata_map *collision;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	collision = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_collision]), line,
			ctrl->mapping_size);

	if (collision)
		return collision->core_id;

	ocf_metadata_error(cache);
	return OCF_CORE_MAX;
}

static uint64_t ocf_metadata_hash_get_core_sector(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	const struct ocf_metadata_map *collision;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	collision = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_collision]), line,
			ctrl->mapping_size);

	if (collision)
		return collision->core_line;

	ocf_metadata_error(cache);
	return ULLONG_MAX;
}

static struct ocf_metadata_uuid *ocf_metadata_hash_get_core_uuid(
		struct ocf_cache *cache, ocf_core_id_t core_id)
{
	struct ocf_metadata_uuid *muuid;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	muuid = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_core_uuid]),
			core_id, sizeof(struct ocf_metadata_uuid));

	if (!muuid)
		ocf_metadata_error(cache);

	return muuid;
}

/*******************************************************************************
 * Core and part id
 ******************************************************************************/

static void ocf_metadata_hash_get_core_and_part_id(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_core_id_t *core_id, ocf_part_id_t *part_id)
{
	const struct ocf_metadata_map *collision;
	const struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	collision = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_collision]), line,
			ctrl->mapping_size);

	info =  ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (collision && info) {
		if (core_id)
			*core_id = collision->core_id;
		if (part_id)
			*part_id = info->partition_id;
	} else {
		ocf_metadata_error(cache);
		if (core_id)
			*core_id = OCF_CORE_MAX;
		if (part_id)
			*part_id = PARTITION_DEFAULT;
	}
}
/*******************************************************************************
 * Hash Table
 ******************************************************************************/

/*
 * Hash Table - Get
 */
static ocf_cache_line_t ocf_metadata_hash_get_hash(
		struct ocf_cache *cache, ocf_cache_line_t index)
{
	ocf_cache_line_t line = cache->device->collision_table_entries;
	int result = 0;
	struct ocf_metadata_hash_ctrl *ctrl
		= (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	result = ocf_metadata_raw_get(cache,
			&(ctrl->raw_desc[metadata_segment_hash]), index,
			&line, sizeof(line));

	if (result)
		ocf_metadata_error(cache);

	return line;
}

/*
 * Hash Table - Set
 */
static void ocf_metadata_hash_set_hash(struct ocf_cache *cache,
		ocf_cache_line_t index, ocf_cache_line_t line)
{
	int result = 0;
	struct ocf_metadata_hash_ctrl *ctrl
		= (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	result = ocf_metadata_raw_set(cache,
			&(ctrl->raw_desc[metadata_segment_hash]), index,
			&line, sizeof(line));

	if (result)
		ocf_metadata_error(cache);
}

/*
 * Hash Table - Get Entries
 */
static ocf_cache_line_t ocf_metadata_hash_entries_hash(
		struct ocf_cache *cache)
{
	struct ocf_metadata_hash_ctrl *ctrl
		= (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	return ctrl->raw_desc[metadata_segment_hash].entries;
}

/*******************************************************************************
 * Cleaning Policy
 ******************************************************************************/

/*
 * Cleaning policy - Get
 */
static void ocf_metadata_hash_get_cleaning_policy(
		struct ocf_cache *cache, ocf_cache_line_t line,
		struct cleaning_policy_meta *cleaning_policy)
{
	int result = 0;
	struct ocf_metadata_hash_ctrl *ctrl
		= (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	result = ocf_metadata_raw_get(cache,
			&(ctrl->raw_desc[metadata_segment_cleaning]), line,
			cleaning_policy, sizeof(*cleaning_policy));

	if (result)
		ocf_metadata_error(cache);
}

/*
 * Cleaning policy - Set
 */
static void ocf_metadata_hash_set_cleaning_policy(
		struct ocf_cache *cache, ocf_cache_line_t line,
		struct cleaning_policy_meta *cleaning_policy)
{
	int result = 0;
	struct ocf_metadata_hash_ctrl *ctrl
		= (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	result = ocf_metadata_raw_set(cache,
			&(ctrl->raw_desc[metadata_segment_cleaning]), line,
			cleaning_policy, sizeof(*cleaning_policy));

	if (result)
		ocf_metadata_error(cache);
}

/*******************************************************************************
 *  Eviction policy
 ******************************************************************************/

/*
 * Eviction policy - Get
 */
static void ocf_metadata_hash_get_eviction_policy(
		struct ocf_cache *cache, ocf_cache_line_t line,
		union eviction_policy_meta *eviction_policy)
{
	int result = 0;
	struct ocf_metadata_hash_ctrl *ctrl
		= (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	result = ocf_metadata_raw_get(cache,
			&(ctrl->raw_desc[metadata_segment_eviction]), line,
			eviction_policy, sizeof(*eviction_policy));

	if (result)
		ocf_metadata_error(cache);
}

/*
 * Cleaning policy - Set
 */
static void ocf_metadata_hash_set_eviction_policy(
		struct ocf_cache *cache, ocf_cache_line_t line,
		union eviction_policy_meta *eviction_policy)
{
	int result = 0;
	struct ocf_metadata_hash_ctrl *ctrl
		= (struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	result = ocf_metadata_raw_set(cache,
			&(ctrl->raw_desc[metadata_segment_eviction]), line,
			eviction_policy, sizeof(*eviction_policy));

	if (result)
		ocf_metadata_error(cache);
}

/*******************************************************************************
 *  Collision
 ******************************************************************************/
static ocf_cache_line_t ocf_metadata_hash_map_lg2phy_seq(
		struct ocf_cache *cache, ocf_cache_line_t coll_idx)
{
	return coll_idx;
}

static ocf_cache_line_t ocf_metadata_hash_map_phy2lg_seq(
		struct ocf_cache *cache, ocf_cache_line_t cache_line)
{
	return cache_line;
}

static ocf_cache_line_t ocf_metadata_hash_map_lg2phy_striping(
		struct ocf_cache *cache, ocf_cache_line_t coll_idx)
{
	ocf_cache_line_t cache_line = 0, offset = 0;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;
	unsigned int entries_in_page =
		ctrl->raw_desc[metadata_segment_collision].entries_in_page;
	unsigned int pages =
		ctrl->raw_desc[metadata_segment_collision].ssd_pages;
	ocf_cache_line_t collision_table_entries =
			cache->device->collision_table_entries;
	ocf_cache_line_t delta =
			(entries_in_page * pages) - collision_table_entries;
	unsigned int row = coll_idx % entries_in_page;

	if (row > entries_in_page - delta)
		offset = row - (entries_in_page - delta);
	else
		offset = 0;

	cache_line = (row * pages) +  (coll_idx / entries_in_page) - offset;
	return cache_line;
}

static ocf_cache_line_t ocf_metadata_hash_map_phy2lg_striping(
		struct ocf_cache *cache, ocf_cache_line_t cache_line)
{
	ocf_cache_line_t coll_idx = 0;

	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	struct ocf_metadata_raw *raw =
		&ctrl->raw_desc[metadata_segment_collision];

	unsigned int pages = raw->ssd_pages;
	unsigned int entries_in_page = raw->entries_in_page;
	unsigned int entries_in_last_page = raw->entries % entries_in_page ?:
			entries_in_page;

	unsigned int row = 0, coll = 0;

	unsigned int last = entries_in_last_page * pages;

	if (cache_line < last) {
		row = cache_line % pages;
		coll = cache_line / pages;
	} else {
		cache_line -= last;
		row = cache_line % (pages - 1);
		coll = cache_line / (pages - 1) + entries_in_last_page;
	}

	coll_idx = (row * entries_in_page) + coll;

	return coll_idx;
}

static void ocf_metadata_hash_set_collision_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next, ocf_cache_line_t prev)
{
	struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (info) {
		info->next_col = next;
		info->prev_col = prev;
	} else {
		ocf_metadata_error(cache);
	}
}

static void ocf_metadata_hash_set_collision_next(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next)
{
	struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (info)
		info->next_col = next;
	else
		ocf_metadata_error(cache);
}

static void ocf_metadata_hash_set_collision_prev(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t prev)
{
	struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (info)
		info->prev_col = prev;
	else
		ocf_metadata_error(cache);
}

static void ocf_metadata_hash_get_collision_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t *next, ocf_cache_line_t *prev)
{
	const struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	ENV_BUG_ON(NULL == next && NULL == prev);

	info = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));
	if (info) {
		if (next)
			*next = info->next_col;
		if (prev)
			*prev = info->prev_col;
	} else {
		ocf_metadata_error(cache);

		if (next)
			*next = cache->device->collision_table_entries;
		if (prev)
			*prev = cache->device->collision_table_entries;
	}
}

static ocf_cache_line_t ocf_metadata_hash_get_collision_next(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	const struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));
	if (info)
		return info->next_col;

	ocf_metadata_error(cache);
	return cache->device->collision_table_entries;
}

static ocf_cache_line_t ocf_metadata_hash_get_collision_prev(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	const struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));
	if (info)
		return info->prev_col;

	ocf_metadata_error(cache);
	return cache->device->collision_table_entries;
}

/*******************************************************************************
 *  Partition
 ******************************************************************************/

static ocf_part_id_t ocf_metadata_hash_get_partition_id(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	const struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (info)
		return info->partition_id;

	ocf_metadata_error(cache);
	return PARTITION_DEFAULT;
}

static ocf_cache_line_t ocf_metadata_hash_get_partition_next(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	const struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (info)
		return info->partition_next;

	ocf_metadata_error(cache);
	return PARTITION_DEFAULT;
}

static ocf_cache_line_t ocf_metadata_hash_get_partition_prev(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	const struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (info)
		return info->partition_prev;

	ocf_metadata_error(cache);
	return PARTITION_DEFAULT;
}

static void ocf_metadata_hash_get_partition_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_part_id_t *part_id, ocf_cache_line_t *next_line,
		ocf_cache_line_t *prev_line)
{
	const struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (info) {
		if (part_id)
			*part_id = info->partition_id;
		if (next_line)
			*next_line = info->partition_next;
		if (prev_line)
			*prev_line = info->partition_prev;
	} else {
		ocf_metadata_error(cache);
		if (part_id)
			*part_id = PARTITION_DEFAULT;
		if (next_line)
			*next_line = cache->device->collision_table_entries;
		if (prev_line)
			*prev_line = cache->device->collision_table_entries;
	}
}

static void ocf_metadata_hash_set_partition_next(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next_line)
{
	struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (info)
		info->partition_next = next_line;
	else
		ocf_metadata_error(cache);
}

static void ocf_metadata_hash_set_partition_prev(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t prev_line)
{
	struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (info)
		info->partition_prev = prev_line;
	else
		ocf_metadata_error(cache);
}

static void ocf_metadata_hash_set_partition_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_part_id_t part_id, ocf_cache_line_t next_line,
		ocf_cache_line_t prev_line)
{
	struct ocf_metadata_list_info *info;
	struct ocf_metadata_hash_ctrl *ctrl =
		(struct ocf_metadata_hash_ctrl *) cache->metadata.iface_priv;

	info = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line,
			sizeof(*info));

	if (info) {
		info->partition_id = part_id;
		info->partition_next = next_line;
		info->partition_prev = prev_line;
	} else {
		ocf_metadata_error(cache);
	}
}

/*******************************************************************************
 * Hash Metadata interface definition
 ******************************************************************************/

static const struct ocf_metadata_iface metadata_hash_iface = {
	.init = ocf_metadata_hash_init,
	.deinit = ocf_metadata_hash_deinit,
	.init_variable_size = ocf_metadata_hash_init_variable_size,
	.deinit_variable_size = ocf_metadata_hash_deinit_variable_size,
	.init_hash_table = ocf_metadata_hash_init_hash_table,

	.layout_iface = NULL,
	.pages = ocf_metadata_hash_pages,
	.cachelines = ocf_metadata_hash_cachelines,
	.size_of = ocf_metadata_hash_size_of,

	/*
	 * Load all, flushing all, etc...
	 */
	.flush_all = ocf_metadata_hash_flush_all,
	.flush_mark = ocf_metadata_hash_flush_mark,
	.flush_do_asynch = ocf_metadata_hash_flush_do_asynch,
	.load_all = ocf_metadata_hash_load_all,
	.load_recovery = ocf_metadata_hash_load_recovery,

	/*
	 * Super Block
	 */
	.set_shutdown_status = ocf_metadata_hash_set_shutdown_status,
	.flush_superblock = ocf_metadata_hash_flush_superblock,
	.load_superblock = ocf_metadata_hash_load_superblock,

	/*
	 * Reserved area
	 */
	.get_reserved_lba = ocf_metadata_hash_get_reserved_lba,

	/*
	 * Core Info
	 */
	.set_core_info = ocf_metadata_hash_set_core_info,
	.get_core_info = ocf_metadata_hash_get_core_info,
	.get_core_id = ocf_metadata_hash_get_core_id,
	.get_core_sector = ocf_metadata_hash_get_core_sector,
	.get_core_uuid  = ocf_metadata_hash_get_core_uuid,

	/*
	 * Core and part id
	 */

	.get_core_and_part_id = ocf_metadata_hash_get_core_and_part_id,

	/*
	 * Collision Info
	 */
	.get_collision_info = ocf_metadata_hash_get_collision_info,
	.set_collision_info = ocf_metadata_hash_set_collision_info,
	.set_collision_next = ocf_metadata_hash_set_collision_next,
	.set_collision_prev = ocf_metadata_hash_set_collision_prev,
	.get_collision_next = ocf_metadata_hash_get_collision_next,
	.get_collision_prev = ocf_metadata_hash_get_collision_prev,

	/*
	 * Partition Info
	 */
	.get_partition_id = ocf_metadata_hash_get_partition_id,
	.get_partition_next = ocf_metadata_hash_get_partition_next,
	.get_partition_prev = ocf_metadata_hash_get_partition_prev,
	.get_partition_info = ocf_metadata_hash_get_partition_info,
	.set_partition_next = ocf_metadata_hash_set_partition_next,
	.set_partition_prev = ocf_metadata_hash_set_partition_prev,
	.set_partition_info = ocf_metadata_hash_set_partition_info,

	/*
	 * Hash Table
	 */
	.get_hash = ocf_metadata_hash_get_hash,
	.set_hash = ocf_metadata_hash_set_hash,
	.entries_hash = ocf_metadata_hash_entries_hash,

	/*
	 * Cleaning Policy
	 */
	.get_cleaning_policy = ocf_metadata_hash_get_cleaning_policy,
	.set_cleaning_policy = ocf_metadata_hash_set_cleaning_policy,

	/*
	 * Eviction Policy
	 */
	.get_eviction_policy = ocf_metadata_hash_get_eviction_policy,
	.set_eviction_policy = ocf_metadata_hash_set_eviction_policy,
};

/*******************************************************************************
 *  Bitmap status
 ******************************************************************************/

#include "metadata_bit.h"

static const struct ocf_metadata_layout_iface layout_ifaces[ocf_metadata_layout_max] = {
	[ocf_metadata_layout_striping] = {
		.init_freelist = ocf_metadata_hash_init_freelist_striping,
		.lg2phy = ocf_metadata_hash_map_lg2phy_striping,
		.phy2lg = ocf_metadata_hash_map_phy2lg_striping
	},
	[ocf_metadata_layout_seq] = {
		.init_freelist = ocf_metadata_hash_init_freelist_seq,
		.lg2phy = ocf_metadata_hash_map_lg2phy_seq,
		.phy2lg = ocf_metadata_hash_map_phy2lg_seq
	}
};


static void ocf_metadata_hash_init_iface(struct ocf_cache *cache,
		ocf_metadata_layout_t layout)
{
	struct ocf_metadata_iface *iface = (struct ocf_metadata_iface *)
			&cache->metadata.iface;

	ENV_BUG_ON(layout >= ocf_metadata_layout_max || layout < 0);

	/* Initialize metadata location interface*/
	if (cache->device->init_mode == ocf_init_mode_metadata_volatile)
		layout = ocf_metadata_layout_seq;
	iface->layout_iface = &layout_ifaces[layout];

	/* Initialize bit status function */

	switch (cache->metadata.settings.size) {
	case ocf_cache_line_size_4:
		iface->test_dirty = _ocf_metadata_test_dirty_u8;
		iface->test_out_dirty = _ocf_metadata_test_out_dirty_u8;
		iface->clear_dirty = _ocf_metadata_clear_dirty_u8;
		iface->set_dirty = _ocf_metadata_set_dirty_u8;
		iface->test_and_set_dirty = _ocf_metadata_test_and_set_dirty_u8;
		iface->test_and_clear_dirty =
				_ocf_metadata_test_and_clear_dirty_u8;
		iface->test_valid = _ocf_metadata_test_valid_u8;
		iface->test_out_valid = _ocf_metadata_test_out_valid_u8;
		iface->clear_valid = _ocf_metadata_clear_valid_u8;
		iface->set_valid = _ocf_metadata_set_valid_u8;
		iface->test_and_set_valid = _ocf_metadata_test_and_set_valid_u8;
		iface->test_and_clear_valid =
				_ocf_metadata_test_and_clear_valid_u8;
		break;

	case ocf_cache_line_size_8:
		iface->test_dirty = _ocf_metadata_test_dirty_u16;
		iface->test_out_dirty = _ocf_metadata_test_out_dirty_u16;
		iface->clear_dirty = _ocf_metadata_clear_dirty_u16;
		iface->set_dirty = _ocf_metadata_set_dirty_u16;
		iface->test_and_set_dirty =
				_ocf_metadata_test_and_set_dirty_u16;
		iface->test_and_clear_dirty =
				_ocf_metadata_test_and_clear_dirty_u16;
		iface->test_valid = _ocf_metadata_test_valid_u16;
		iface->test_out_valid = _ocf_metadata_test_out_valid_u16;
		iface->clear_valid = _ocf_metadata_clear_valid_u16;
		iface->set_valid = _ocf_metadata_set_valid_u16;
		iface->test_and_set_valid =
				_ocf_metadata_test_and_set_valid_u16;
		iface->test_and_clear_valid =
				_ocf_metadata_test_and_clear_valid_u16;
		break;

	case ocf_cache_line_size_16:
		iface->test_dirty = _ocf_metadata_test_dirty_u32;
		iface->test_out_dirty = _ocf_metadata_test_out_dirty_u32;
		iface->clear_dirty = _ocf_metadata_clear_dirty_u32;
		iface->set_dirty = _ocf_metadata_set_dirty_u32;
		iface->test_and_set_dirty =
				_ocf_metadata_test_and_set_dirty_u32;
		iface->test_and_clear_dirty =
				_ocf_metadata_test_and_clear_dirty_u32;
		iface->test_valid = _ocf_metadata_test_valid_u32;
		iface->test_out_valid = _ocf_metadata_test_out_valid_u32;
		iface->clear_valid = _ocf_metadata_clear_valid_u32;
		iface->set_valid = _ocf_metadata_set_valid_u32;
		iface->test_and_set_valid =
				_ocf_metadata_test_and_set_valid_u32;
		iface->test_and_clear_valid =
				_ocf_metadata_test_and_clear_valid_u32;
		break;
	case ocf_cache_line_size_32:
		iface->test_dirty = _ocf_metadata_test_dirty_u64;
		iface->test_out_dirty = _ocf_metadata_test_out_dirty_u64;
		iface->clear_dirty = _ocf_metadata_clear_dirty_u64;
		iface->set_dirty = _ocf_metadata_set_dirty_u64;
		iface->test_and_set_dirty =
				_ocf_metadata_test_and_set_dirty_u64;
		iface->test_and_clear_dirty =
				_ocf_metadata_test_and_clear_dirty_u64;
		iface->test_valid = _ocf_metadata_test_valid_u64;
		iface->test_out_valid = _ocf_metadata_test_out_valid_u64;
		iface->clear_valid = _ocf_metadata_clear_valid_u64;
		iface->set_valid = _ocf_metadata_set_valid_u64;
		iface->test_and_set_valid =
				_ocf_metadata_test_and_set_valid_u64;
		iface->test_and_clear_valid =
				_ocf_metadata_test_and_clear_valid_u64;
		break;

	case ocf_cache_line_size_64:
		iface->test_dirty = _ocf_metadata_test_dirty_u128;
		iface->test_out_dirty = _ocf_metadata_test_out_dirty_u128;
		iface->clear_dirty = _ocf_metadata_clear_dirty_u128;
		iface->set_dirty = _ocf_metadata_set_dirty_u128;
		iface->test_and_set_dirty =
				_ocf_metadata_test_and_set_dirty_u128;
		iface->test_and_clear_dirty =
				_ocf_metadata_test_and_clear_dirty_u128;
		iface->test_valid = _ocf_metadata_test_valid_u128;
		iface->test_out_valid = _ocf_metadata_test_out_valid_u128;
		iface->clear_valid = _ocf_metadata_clear_valid_u128;
		iface->set_valid = _ocf_metadata_set_valid_u128;
		iface->test_and_set_valid =
				_ocf_metadata_test_and_set_valid_u128;
		iface->test_and_clear_valid =
				_ocf_metadata_test_and_clear_valid_u128;
		break;

	default:
		ENV_BUG();
		break;
	}
}

/*
 * Get metadata hash interface
 */
const struct ocf_metadata_iface *metadata_hash_get_iface(void)
{
	return &metadata_hash_iface;
}
