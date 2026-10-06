/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_LAYOUT_H__
#define __METADATA_LAYOUT_H__

#include "ocf/ocf.h"
#include "../ocf_def_priv.h"
#include "metadata_segment_id.h"

/*
 * On-disk metadata layout.
 *
 * Metadata segments are placed on cache device one after another, in order
 * of enum ocf_metadata_segment_id, starting at page 0. Each segment consists
 * of pages holding entries (entries never cross page boundary, remainder of
 * page is unused), rounded up to OCF_METADATA_SEGMENT_ALIGNMENT. Segments
 * that support flapping are stored twice (two consecutive copies).
 *
 * Fixed size segments do not depend on cache configuration. Size of
 * variable size segments depends on cache line size and number of cache
 * lines. Cleaning segment is not present when cleaner is disabled.
 */

/** Alignment of each segment copy on disk */
#define OCF_METADATA_SEGMENT_ALIGNMENT (128 * KiB)

struct ocf_metadata_segment_layout {
	enum ocf_metadata_segment_id id;
		/*!< Segment id */

	uint32_t entry_size;
		/*!< Size of single entry */

	uint32_t entries_in_page;
		/*!< Number of entries in one page */

	uint64_t entries;
		/*!< Number of entries */

	uint64_t pages;
		/*!< Number of pages holding entries (single copy) */

	uint64_t offset;
		/*!< First page of segment on disk */

	bool flapping;
		/*!< Segment is stored in two copies */

	bool disabled;
		/*!< Segment is not present */
};

struct ocf_metadata_layout {
	bool on_disk;
		/*!< False if metadata is volatile (no space on disk) */

	ocf_cache_line_size_t line_size;
		/*!< Cache line size */

	ocf_cache_line_t cachelines;
		/*!< Number of cache lines */

	uint32_t pages_fixed;
		/*!< Pages occupied by fixed size segments */

	uint32_t pages_variable;
		/*!< Pages occupied by variable size segments */

	struct ocf_metadata_segment_layout segment[metadata_segment_max];
};

/**
 * @brief Number of entries in metadata segment
 */
ocf_cache_line_t ocf_metadata_segment_layout_entries(
		enum ocf_metadata_segment_id segment,
		ocf_cache_line_t cachelines);

/**
 * @brief Size of single entry in metadata segment
 */
uint32_t ocf_metadata_segment_layout_entry_size(
		enum ocf_metadata_segment_id segment,
		ocf_cache_line_size_t line_size);

/**
 * @brief Check if metadata segment is stored in two copies
 */
bool ocf_metadata_segment_layout_is_flapped(
		enum ocf_metadata_segment_id segment);

static inline uint32_t _ocf_metadata_layout_aligned_pages(uint64_t pages)
{
	const uint32_t alignment = OCF_METADATA_SEGMENT_ALIGNMENT / PAGE_SIZE;

	return OCF_DIV_ROUND_UP(pages, alignment) * alignment;
}

/**
 * @brief Number of pages occupied by segment on disk (all copies included)
 */
static inline uint32_t ocf_metadata_segment_layout_pages(
		const struct ocf_metadata_segment_layout *segment)
{
	return _ocf_metadata_layout_aligned_pages(segment->pages) *
			(segment->flapping ? 2 : 1);
}

/**
 * @brief First page of given copy of segment on disk
 *
 * @param segment - Segment layout
 * @param flapping_idx - Index of segment copy (0 if segment is not flapped)
 */
static inline uint64_t ocf_metadata_segment_layout_offset(
		const struct ocf_metadata_segment_layout *segment,
		unsigned flapping_idx)
{
	return segment->offset +
		_ocf_metadata_layout_aligned_pages(segment->pages) *
		flapping_idx;
}

/**
 * @brief Checksum of superblock config
 *
 * Checksum covers struct ocf_superblock_config up to the checksum array.
 *
 * @param data - Superblock config (struct ocf_superblock_config)
 */
uint32_t ocf_metadata_segment_layout_checksum_superblock(const void *data);

/**
 * @brief Update segment checksum with single page of segment data
 *
 * @param segment - Segment layout (other than superblock config)
 * @param crc - Checksum of preceding pages (0 for first page)
 * @param page - Page of segment data
 */
uint32_t ocf_metadata_segment_layout_checksum_page(
		const struct ocf_metadata_segment_layout *segment, uint32_t crc,
		const void *page);

/**
 * @brief Checksum of segment data
 *
 * Checksum covers all pages of segment data as kept in memory, i.e. entries
 * packed densely one after another (without unused remainder of each page
 * on disk), followed by zeros up to the number of pages of the segment.
 *
 * @param segment - Segment layout (other than superblock config)
 * @param get_page - Callback returning page of segment data of given index
 * @param opaque - Private data passed to @get_page
 */
uint32_t ocf_metadata_segment_layout_checksum_segment(
		const struct ocf_metadata_segment_layout *segment,
		const void *(*get_page)(void *opaque, unsigned idx),
		void *opaque);

/**
 * @brief Initialize layout of fixed size segments
 *
 * @param layout - Layout to be initialized
 * @param on_disk - False if metadata is volatile
 */
void ocf_metadata_layout_init_fixed_size(
		struct ocf_metadata_layout *layout, bool on_disk);

/**
 * @brief Set up layout of variable size segments for given number of
 *	cache lines
 *
 * @param layout - Layout with fixed size segments initialized
 * @param line_size - Cache line size
 * @param cachelines - Number of cache lines
 * @param cleaner_disabled - True if cleaning segment is not present
 */
void ocf_metadata_layout_set_cachelines(struct ocf_metadata_layout *layout,
		ocf_cache_line_size_t line_size, ocf_cache_line_t cachelines,
		bool cleaner_disabled);

/**
 * @brief Find number of cache lines that fit on device together with
 *	metadata and set up layout of variable size segments accordingly
 *
 * @param layout - Layout with fixed size segments initialized
 * @param line_size - Cache line size
 * @param device_lines - Size of cache device in cache lines
 * @param cleaner_disabled - True if cleaning segment is not present
 * @param[out] inexact - Set to true if exact fit was not found and
 *	accepted result leaves some space unused
 *
 * @retval 0 Success
 * @retval -OCF_ERR_INVAL Calculation did not converge
 * @retval -OCF_ERR_INVAL_CACHE_DEV Metadata does not fit on device
 */
int ocf_metadata_layout_fit(struct ocf_metadata_layout *layout,
		ocf_cache_line_size_t line_size, uint64_t device_lines,
		bool cleaner_disabled, bool *inexact);

/**
 * @brief Total number of pages occupied by metadata on disk
 */
static inline uint32_t ocf_metadata_layout_pages(
		const struct ocf_metadata_layout *layout)
{
	return layout->pages_fixed + layout->pages_variable;
}

#endif /* __METADATA_LAYOUT_H__ */
