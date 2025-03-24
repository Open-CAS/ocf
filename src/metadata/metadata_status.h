/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2025 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_STATUS_H__
#define __METADATA_STATUS_H__

#include "../concurrency/ocf_metadata_concurrency.h"
#include "metadata_cache_line.h"

/*******************************************************************************
 * Dirty
 ******************************************************************************/

bool ocf_metadata_test_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);
bool ocf_metadata_test_out_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);
bool ocf_metadata_clear_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);
bool ocf_metadata_set_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);
bool ocf_metadata_test_and_set_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);
bool ocf_metadata_test_and_clear_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);

bool ocf_metadata_test_valid(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);
bool ocf_metadata_test_out_valid(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);
bool ocf_metadata_clear_valid(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);
bool ocf_metadata_set_valid(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);
bool ocf_metadata_test_and_set_valid(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);
bool ocf_metadata_test_and_clear_valid(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop, bool all);
bool ocf_metadata_clear_valid_if_clean(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);
void ocf_metadata_clear_dirty_if_invalid(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop);

static inline void metadata_init_status_bits(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	ocf_metadata_clear_dirty(cache, line, 0, ocf_line_end_sector(cache));
	ocf_metadata_clear_valid(cache, line, 0, ocf_line_end_sector(cache));
}

static inline bool metadata_test_dirty_all(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	bool test;

	test = ocf_metadata_test_dirty(cache, line, 0,
			ocf_line_end_sector(cache), true);

	return test;
}

static inline bool metadata_test_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	bool test;

	test = ocf_metadata_test_dirty(cache, line, 0,
			ocf_line_end_sector(cache), false);

	return test;
}

static inline void metadata_set_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	ocf_metadata_set_dirty(cache, line, 0, ocf_line_end_sector(cache));
}

static inline void metadata_clear_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	ocf_metadata_clear_dirty(cache, line, 0, ocf_line_end_sector(cache));
}

static inline bool metadata_test_and_clear_dirty(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	return ocf_metadata_test_and_clear_dirty(cache, line, 0,
			ocf_line_end_sector(cache), false);
}

static inline bool metadata_test_and_set_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	return ocf_metadata_test_and_set_dirty(cache, line, 0,
			ocf_line_end_sector(cache), false);
}

/*******************************************************************************
 * Dirty - Sector Implementation
 ******************************************************************************/

static inline bool metadata_test_dirty_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	return ocf_metadata_test_dirty(cache, line,
			start, stop, false);
}

static inline bool metadata_test_dirty_all_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	return ocf_metadata_test_dirty(cache, line,
			start, stop, true);
}

static inline bool metadata_test_dirty_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	return metadata_test_dirty_sec(cache, line, pos, pos);
}

static inline bool metadata_test_dirty_out_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	return ocf_metadata_test_out_dirty(cache, line, start, stop);
}

static inline void metadata_set_dirty_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	ocf_metadata_set_dirty(cache, line, start, stop);
}

static inline void metadata_clear_dirty_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	ocf_metadata_clear_dirty(cache, line, start, stop);
}

static inline void metadata_set_dirty_sec_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	ocf_metadata_set_dirty(cache, line, pos, pos);
}

static inline void metadata_clear_dirty_sec_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	ocf_metadata_clear_dirty(cache, line, pos, pos);
}

static inline bool metadata_test_and_clear_dirty_sec(
		struct ocf_cache *cache, ocf_cache_line_t line,
		uint8_t start, uint8_t stop)
{
	return ocf_metadata_test_and_clear_dirty(cache, line,
			start, stop, false);
}

/*
 * Marks given cache line's bits as clean
 *
 * @return true if any cache line's sector was dirty and became clean
 * @return false for other cases
 */
static inline bool metadata_clear_dirty_sec_changed(
		struct ocf_cache *cache, ocf_cache_line_t line,
		uint8_t start, uint8_t stop, bool *line_is_clean)
{
	bool sec_changed;

	sec_changed = ocf_metadata_test_dirty(cache, line,
			start, stop, false);
	*line_is_clean = !ocf_metadata_clear_dirty(cache, line,
			start, stop);

	return sec_changed;
}

/*
 * Marks given cache line's bits as dirty
 *
 * @return true if any cache line's sector became dirty
 * @return false for other cases
 */
static inline bool metadata_set_dirty_sec_changed(
		struct ocf_cache *cache, ocf_cache_line_t line,
		uint8_t start, uint8_t stop, bool *line_was_dirty)
{
	bool sec_changed;

	sec_changed = !ocf_metadata_test_dirty(cache, line,
			start, stop, true);
	*line_was_dirty = ocf_metadata_set_dirty(cache, line, start,
			stop);

	return sec_changed;
}

/*******************************************************************************
 * Valid
 ******************************************************************************/

static inline bool metadata_test_valid_any(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	return ocf_metadata_test_valid(cache, line, 0,
			ocf_line_end_sector(cache), false);
}

static inline bool metadata_test_valid(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	return ocf_metadata_test_valid(cache, line, 0,
			ocf_line_end_sector(cache), true);
}

static inline void metadata_set_valid(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	ocf_metadata_set_valid(cache, line, 0, ocf_line_end_sector(cache));
}

static inline void metadata_clear_valid(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	ocf_metadata_clear_valid(cache, line, 0, ocf_line_end_sector(cache));
}

static inline bool metadata_clear_valid_if_clean(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	return ocf_metadata_clear_valid_if_clean(cache, line, 0,
			ocf_line_end_sector(cache));
}

static inline bool metadata_test_and_clear_valid(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	return ocf_metadata_test_and_clear_valid(cache, line, 0,
			ocf_line_end_sector(cache), true);
}

static inline bool metadata_test_and_set_valid(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	return ocf_metadata_test_and_set_valid(cache, line, 0,
			ocf_line_end_sector(cache), true);
}

static inline void metadata_clear_dirty_if_invalid(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	ocf_metadata_clear_dirty_if_invalid(cache, line, 0,
			ocf_line_end_sector(cache));
}

/*******************************************************************************
 * Valid - Sector Implementation
 ******************************************************************************/

static inline bool metadata_test_valid_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	return ocf_metadata_test_valid(cache, line,
			start, stop, true);
}

static inline bool metadata_test_valid_any_out_sec(
		struct ocf_cache *cache, ocf_cache_line_t line,
		uint8_t start, uint8_t stop)
{
	return ocf_metadata_test_out_valid(cache, line,
			start, stop);
}

static inline bool metadata_test_valid_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	return metadata_test_valid_sec(cache, line, pos, pos);
}

/*
 * Marks given cache line's bits as valid
 *
 * @return true if any of the cache line's bits was valid before this operation
 * @return false if the cache line was invalid (all bits invalid) before this
 * operation
 */
static inline bool metadata_set_valid_sec_changed(
		struct ocf_cache *cache, ocf_cache_line_t line,
		uint8_t start, uint8_t stop)
{
	return !ocf_metadata_set_valid(cache, line,
			start, stop);
}

static inline void metadata_clear_valid_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	ocf_metadata_clear_valid(cache, line, start, stop);
}

static inline void metadata_clear_valid_sec_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	ocf_metadata_clear_valid(cache, line, pos, pos);
}

static inline void metadata_set_valid_sec_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	ocf_metadata_set_valid(cache, line, pos, pos);
}
/*
 * Marks given cache line's sectors as invalid
 *
 * @return true if line was valid and became invalid (all sectors invalid)
 * @return false if line was invalid and remains invalid or
 *		if line was valid and still has valid sectors
 */
static inline bool metadata_clear_valid_sec_changed(
		struct ocf_cache *cache, ocf_cache_line_t line,
		uint8_t start, uint8_t stop, bool *line_remains_valid)
{
	bool line_was_valid, _line_remains_valid;

	line_was_valid = ocf_metadata_test_valid(cache, line, 0,
			ocf_line_end_sector(cache), false);

	_line_remains_valid = ocf_metadata_clear_valid(cache, line,
			start, stop);

	if (likely(line_remains_valid != NULL))
		*line_remains_valid = _line_remains_valid;

	return line_was_valid && !_line_remains_valid;
}

#endif /* METADATA_STATUS_H_ */
