/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_STATUS_H__
#define __METADATA_STATUS_H__

#include "../concurrency/ocf_metadata_concurrency.h"

/*******************************************************************************
 * Dirty
 ******************************************************************************/

static inline void metadata_init_status_bits(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	OCF_METADATA_BITS_LOCK_WR();

	cache->metadata.iface.clear_dirty(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end);
	cache->metadata.iface.clear_valid(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end);

	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline bool metadata_test_dirty_all(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	bool test;

	OCF_METADATA_BITS_LOCK_RD();
	test = cache->metadata.iface.test_dirty(cache, line,
		cache->metadata.settings.sector_start,
		cache->metadata.settings.sector_end, true);
	OCF_METADATA_BITS_UNLOCK_RD();

	return test;
}

static inline bool metadata_test_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	bool test;

	OCF_METADATA_BITS_LOCK_RD();
	test = cache->metadata.iface.test_dirty(cache, line,
		cache->metadata.settings.sector_start,
		cache->metadata.settings.sector_end, false);
	OCF_METADATA_BITS_UNLOCK_RD();

	return test;
}

static inline void metadata_set_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.set_dirty(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end);
	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline void metadata_clear_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.clear_dirty(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end);
	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline bool metadata_test_and_clear_dirty(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	bool test;

	OCF_METADATA_BITS_LOCK_WR();
	test =	cache->metadata.iface.test_and_clear_dirty(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end, false);
	OCF_METADATA_BITS_UNLOCK_WR();

	return test;
}

static inline bool metadata_test_and_set_dirty(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	bool test;

	OCF_METADATA_BITS_LOCK_WR();
	test =	cache->metadata.iface.test_and_set_dirty(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end, false);
	OCF_METADATA_BITS_UNLOCK_WR();

	return test;
}

/*******************************************************************************
 * Dirty - Sector Implementation
 ******************************************************************************/

static inline bool metadata_test_dirty_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	bool test;

	OCF_METADATA_BITS_LOCK_RD();
	test = cache->metadata.iface.test_dirty(cache, line,
			start, stop, false);
	OCF_METADATA_BITS_UNLOCK_RD();

	return test;
}

static inline bool metadata_test_dirty_all_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	bool test;

	OCF_METADATA_BITS_LOCK_RD();
	test = cache->metadata.iface.test_dirty(cache, line,
			start, stop, true);
	OCF_METADATA_BITS_UNLOCK_RD();

	return test;
}

static inline bool metadata_test_dirty_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	return metadata_test_dirty_sec(cache, line, pos, pos);
}

static inline bool metadata_test_dirty_out_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	bool test;

	OCF_METADATA_BITS_LOCK_RD();
	test = cache->metadata.iface.test_out_dirty(cache, line, start, stop);
	OCF_METADATA_BITS_UNLOCK_RD();

	return test;
}

static inline void metadata_set_dirty_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.set_dirty(cache, line, start, stop);
	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline void metadata_clear_dirty_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.clear_dirty(cache, line, start, stop);
	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline void metadata_set_dirty_sec_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.set_dirty(cache, line, pos, pos);
	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline void metadata_clear_dirty_sec_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.clear_dirty(cache, line, pos, pos);
	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline bool metadata_test_and_clear_dirty_sec(
		struct ocf_cache *cache, ocf_cache_line_t line,
		uint8_t start, uint8_t stop)
{
	bool test = false;

	OCF_METADATA_BITS_LOCK_WR();
	test = cache->metadata.iface.test_and_clear_dirty(cache, line,
			start, stop, false);
	OCF_METADATA_BITS_UNLOCK_WR();

	return test;
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

	OCF_METADATA_BITS_LOCK_WR();

	sec_changed = cache->metadata.iface.test_dirty(cache, line,
			start, stop, false);
	*line_is_clean = !cache->metadata.iface.clear_dirty(cache, line,
			start, stop);

	OCF_METADATA_BITS_UNLOCK_WR();

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

	OCF_METADATA_BITS_LOCK_WR();
	sec_changed = !cache->metadata.iface.test_dirty(cache, line,
			start, stop, true);
	*line_was_dirty = cache->metadata.iface.set_dirty(cache, line, start,
			stop);
	OCF_METADATA_BITS_UNLOCK_WR();

	return sec_changed;
}

/*******************************************************************************
 * Valid
 ******************************************************************************/

static inline bool metadata_test_valid_any(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	bool test;

	OCF_METADATA_BITS_LOCK_RD();
	test = cache->metadata.iface.test_valid(cache, line,
		cache->metadata.settings.sector_start,
		cache->metadata.settings.sector_end, false);
	OCF_METADATA_BITS_UNLOCK_RD();

	return test;
}

static inline bool metadata_test_valid(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	bool test;

	OCF_METADATA_BITS_LOCK_RD();
	test = cache->metadata.iface.test_valid(cache, line,
		cache->metadata.settings.sector_start,
		cache->metadata.settings.sector_end, true);
	OCF_METADATA_BITS_UNLOCK_RD();

	return test;
}

static inline void metadata_set_valid(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.set_valid(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end);
	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline void metadata_clear_valid(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.clear_valid(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end);
	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline bool metadata_test_and_clear_valid(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	bool test = false;

	OCF_METADATA_BITS_LOCK_WR();
	test =	cache->metadata.iface.test_and_clear_valid(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end, true);
	OCF_METADATA_BITS_UNLOCK_WR();

	return test;
}

static inline bool metadata_test_and_set_valid(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	bool test = false;

	OCF_METADATA_BITS_LOCK_WR();
	test =	cache->metadata.iface.test_and_set_valid(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end, true);
	OCF_METADATA_BITS_UNLOCK_WR();

	return test;
}

/*******************************************************************************
 * Valid - Sector Implementation
 ******************************************************************************/

static inline bool metadata_test_valid_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	bool test;

	OCF_METADATA_BITS_LOCK_RD();
	test = cache->metadata.iface.test_valid(cache, line,
			start, stop, true);
	OCF_METADATA_BITS_UNLOCK_RD();

	return test;
}

static inline bool metadata_test_valid_any_out_sec(
		struct ocf_cache *cache, ocf_cache_line_t line,
		uint8_t start, uint8_t stop)
{
	bool test = false;

	OCF_METADATA_BITS_LOCK_RD();
	test = cache->metadata.iface.test_out_valid(cache, line,
			start, stop);
	OCF_METADATA_BITS_UNLOCK_RD();

	return test;
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
	bool was_any_valid;

	OCF_METADATA_BITS_LOCK_WR();
	was_any_valid = cache->metadata.iface.set_valid(cache, line,
			start, stop);
	OCF_METADATA_BITS_UNLOCK_WR();

	return !was_any_valid;
}

static inline void metadata_clear_valid_sec(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t start, uint8_t stop)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.clear_valid(cache, line, start, stop);
	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline void metadata_clear_valid_sec_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.clear_valid(cache, line, pos, pos);
	OCF_METADATA_BITS_UNLOCK_WR();
}

static inline void metadata_set_valid_sec_one(struct ocf_cache *cache,
		ocf_cache_line_t line, uint8_t pos)
{
	OCF_METADATA_BITS_LOCK_WR();
	cache->metadata.iface.set_valid(cache, line, pos, pos);
	OCF_METADATA_BITS_UNLOCK_WR();
}
/*
 * Marks given cache line's bits as invalid
 *
 * @return true if any of the cache line's bits was valid and the cache line
 * became invalid (all bits invalid) after the operation
 * @return false in other cases
 */
static inline bool metadata_clear_valid_sec_changed(
		struct ocf_cache *cache, ocf_cache_line_t line,
		uint8_t start, uint8_t stop, bool *is_valid)
{
	bool was_any_valid;

	OCF_METADATA_BITS_LOCK_WR();

	was_any_valid = cache->metadata.iface.test_valid(cache, line,
			cache->metadata.settings.sector_start,
			cache->metadata.settings.sector_end, false);

	*is_valid = cache->metadata.iface.clear_valid(cache, line,
			start, stop);

	OCF_METADATA_BITS_UNLOCK_WR();

	return was_any_valid && !*is_valid;
}

#endif /* METADATA_STATUS_H_ */
