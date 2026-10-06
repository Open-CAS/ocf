/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_BIT_H__
#define __METADATA_BIT_H__

#include "metadata_collision.h"

/*
 * Cache line status bits (valid, dirty) stored in collision segment.
 *
 * All functions here operate on single collision segment entry and do not
 * depend on cache object, so they can be used on any buffer holding
 * collision segment, e.g. during metadata migration.
 */

/*******************************************************************************
 * Status layout
 ******************************************************************************/

/**
 * @brief Cache line status types, stored in this order after
 *	struct ocf_metadata_map
 */
enum {
	ocf_metadata_status_type_valid = 0,
	ocf_metadata_status_type_dirty,

	ocf_metadata_status_type_max
};

/**
 * @brief Size of status following struct ocf_metadata_map in collision entry
 */
static inline size_t ocf_metadata_status_sizeof(ocf_cache_line_size_t line_size)
{
	size_t size;

	switch (line_size) {
	case ocf_cache_line_size_4:
#ifdef OCF_BLOCK_SIZE_4K
		/*
		 * We only need one valid and one dirty per line.
		 * Use bitfields from struct ocf_metadata_map.
		 */
		size = 0;
		break;
#endif
	case ocf_cache_line_size_8:
	case ocf_cache_line_size_16:
	case ocf_cache_line_size_32:
	case ocf_cache_line_size_64:
		/* Number of bytes required to mark cache line status */
		size = OCF_DIV_ROUND_UP(BYTES_TO_BLOCKS(line_size), 8);
		break;
	default:
		ENV_BUG();
	}

	/* Number of types of status (valid, dirty, etc...) */
	size *= ocf_metadata_status_type_max;

	/* At the end we have size */
	return size;
}

typedef __uint128_t u128;

/*
 * Collision entry layout for each cache line size. Bit N of valid/dirty
 * describes block N of the cache line (block size is OCF_BLOCK_SIZE).
 *
 * line size | OCF_BLOCK_SIZE_4K         | default (512B blocks)
 * ----------+---------------------------+----------------------
 *  4 KiB    | map._valid, map._dirty    | ocf_metadata_map_u8
 *  8 KiB    | ocf_metadata_map_u8       | ocf_metadata_map_u16
 * 16 KiB    | ocf_metadata_map_u8       | ocf_metadata_map_u32
 * 32 KiB    | ocf_metadata_map_u8       | ocf_metadata_map_u64
 * 64 KiB    | ocf_metadata_map_u16      | ocf_metadata_map_u128
 */
struct ocf_metadata_map_u8 {
	struct ocf_metadata_map map;
	u8 valid;
	u8 dirty;
} __attribute__((packed));

struct ocf_metadata_map_u16 {
	struct ocf_metadata_map map;
	u16 valid;
	u16 dirty;
} __attribute__((packed));

#ifndef OCF_BLOCK_SIZE_4K
struct ocf_metadata_map_u32 {
	struct ocf_metadata_map map;
	u32 valid;
	u32 dirty;
} __attribute__((packed));

struct ocf_metadata_map_u64 {
	struct ocf_metadata_map map;
	u64 valid;
	u64 dirty;
} __attribute__((packed));

struct ocf_metadata_map_u128 {
	struct ocf_metadata_map map;
	u128 valid;
	u128 dirty;
} __attribute__((packed));
#endif

/*******************************************************************************
 * Sector mask getter
 ******************************************************************************/

static inline uint64_t _get_mask(uint8_t start, uint8_t stop)
{
	uint64_t mask = 0;

	ENV_BUG_ON(start >= 64);
	ENV_BUG_ON(stop >= 64);
	ENV_BUG_ON(stop < start);

	mask = ~mask;
	mask >>= start + (63 - stop);
	mask <<= start;

	return mask;
}

#define _get_mask_u8(start, stop) _get_mask(start, stop)
#define _get_mask_u16(start, stop) _get_mask(start, stop)
#define _get_mask_u32(start, stop) _get_mask(start, stop)
#define _get_mask_u64(start, stop) _get_mask(start, stop)

static inline u128 _get_mask_u128(uint8_t start, uint8_t stop)
{
	u128 mask = 0;

	ENV_BUG_ON(start >= 128);
	ENV_BUG_ON(stop >= 128);
	ENV_BUG_ON(stop < start);

	mask = ~mask;
	mask >>= start + (127 - stop);
	mask <<= start;

	return mask;
}

/*******************************************************************************
 * Per entry type status operations
 ******************************************************************************/

#ifdef OCF_BLOCK_SIZE_4K
#define ocf_metadata_bit_func_no_type(what) \
static inline bool _ocf_metadata_test_##what( \
		const struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop, bool all) \
{ \
	ENV_BUG_ON(start != stop); \
\
	if (entry->_##what) { \
		return true; \
	} else { \
		return false; \
	} \
} \
\
static inline bool _ocf_metadata_test_out_##what( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop) \
{ \
	return false; \
} \
\
static inline bool _ocf_metadata_clear_##what(struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop) \
{ \
	ENV_BUG_ON(start != stop); \
\
	entry->_##what = 0; \
\
	return false; \
} \
\
static inline bool _ocf_metadata_set_##what(struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop) \
{ \
	bool result; \
\
	ENV_BUG_ON(start != stop); \
\
	result = entry->_##what ? true : false; \
\
	entry->_##what = 1; \
\
	return result; \
} \
\
static inline bool _ocf_metadata_test_and_set_##what( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop, bool all) \
{ \
	bool test; \
\
	ENV_BUG_ON(start != stop); \
\
	if (entry->_##what) { \
		test = true; \
	} else { \
		test = false; \
	} \
\
	entry->_##what = 1; \
	return test; \
} \
\
static inline bool _ocf_metadata_test_and_clear_##what( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop, bool all) \
{ \
	bool test; \
\
	ENV_BUG_ON(start != stop); \
\
	if (entry->_##what) { \
		test = true; \
	} else { \
		test = false; \
	} \
\
	entry->_##what = 0; \
	return test; \
}

#define ocf_metadata_bit_func_basic_no_type() \
static inline bool _ocf_metadata_clear_valid_if_clean( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop) \
{ \
	ENV_BUG_ON(start != stop); \
\
	entry->_valid = (!entry->_dirty) ? 0 : entry->_valid; \
\
	if (entry->_valid) { \
		return true; \
	} else { \
		return false; \
	} \
} \
\
static inline void _ocf_metadata_clear_dirty_if_invalid( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop) \
{ \
	ENV_BUG_ON(start != stop); \
\
	entry->_dirty = (!entry->_valid) ? 0 : entry->_dirty; \
} \
\
/* true if no incorrect combination of status bits */ \
static inline bool _ocf_metadata_check( \
		const struct ocf_metadata_map *entry) \
{ \
	return (entry->_dirty & (!entry->_valid)) == 0; \
}
#endif

#define ocf_metadata_bit_func(what, type) \
static inline bool _ocf_metadata_test_##what##_##type( \
		const struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop, bool all) \
{ \
	type mask = _get_mask_##type(start, stop); \
\
	const struct ocf_metadata_map_##type *map = (const void *)entry; \
\
	if (all) { \
		if (mask == (map->what & mask)) { \
			return true; \
		} else { \
			return false; \
		} \
	} else { \
		if (map->what & mask) { \
			return true; \
		} else { \
			return false; \
		} \
	} \
} \
\
static inline bool _ocf_metadata_test_out_##what##_##type( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop) \
{ \
	type mask = _get_mask_##type(start, stop); \
\
	const struct ocf_metadata_map_##type *map = (const void *)entry; \
\
	if (map->what & ~mask) { \
		return true; \
	} else { \
		return false; \
	} \
} \
\
static inline bool _ocf_metadata_clear_##what##_##type( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop) \
{ \
	type mask = _get_mask_##type(start, stop); \
\
	struct ocf_metadata_map_##type *map = (void *)entry; \
\
	map->what &= ~mask; \
\
	if (map->what) { \
		return true; \
	} else { \
		return false; \
	} \
} \
\
static inline bool _ocf_metadata_set_##what##_##type( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop) \
{ \
	bool result; \
	type mask = _get_mask_##type(start, stop); \
\
	struct ocf_metadata_map_##type *map = (void *)entry; \
\
	result = map->what ? true : false; \
\
	map->what |= mask; \
\
	return result; \
} \
\
static inline bool _ocf_metadata_test_and_set_##what##_##type( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop, bool all) \
{ \
	bool test; \
	type mask = _get_mask_##type(start, stop); \
\
	struct ocf_metadata_map_##type *map = (void *)entry; \
\
	if (all) { \
		if (mask == (map->what & mask)) { \
			test = true; \
		} else { \
			test = false; \
		} \
	} else { \
		if (map->what & mask) { \
			test = true; \
		} else { \
			test = false; \
		} \
	} \
\
	map->what |= mask; \
	return test; \
} \
\
static inline bool _ocf_metadata_test_and_clear_##what##_##type( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop, bool all) \
{ \
	bool test; \
	type mask = _get_mask_##type(start, stop); \
\
	struct ocf_metadata_map_##type *map = (void *)entry; \
\
	if (all) { \
		if (mask == (map->what & mask)) { \
			test = true; \
		} else { \
			test = false; \
		} \
	} else { \
		if (map->what & mask) { \
			test = true; \
		} else { \
			test = false; \
		} \
	} \
\
	map->what &= ~mask; \
	return test; \
}

#define ocf_metadata_bit_func_basic(type) \
static inline bool _ocf_metadata_clear_valid_if_clean_##type( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop) \
{ \
	type mask = _get_mask_##type(start, stop); \
\
	struct ocf_metadata_map_##type *map = (void *)entry; \
\
	map->valid &= (mask & map->dirty) | (~mask); \
\
	if (map->valid) { \
		return true; \
	} else { \
		return false; \
	} \
} \
\
static inline void _ocf_metadata_clear_dirty_if_invalid_##type( \
		struct ocf_metadata_map *entry, \
		uint8_t start, uint8_t stop) \
{ \
	type mask = _get_mask_##type(start, stop); \
\
	struct ocf_metadata_map_##type *map = (void *)entry; \
\
	map->dirty &= (mask & map->valid) | (~mask); \
} \
\
/* true if no incorrect combination of status bits */ \
static inline bool _ocf_metadata_check_##type( \
		const struct ocf_metadata_map *entry) \
{ \
	const struct ocf_metadata_map_##type *map = (const void *)entry; \
\
	return (map->dirty & (~map->valid)) == 0; \
}

#ifdef OCF_BLOCK_SIZE_4K
#define ocf_metadata_bit_funcs_no_type() \
ocf_metadata_bit_func_no_type(dirty); \
ocf_metadata_bit_func_no_type(valid); \
ocf_metadata_bit_func_basic_no_type()
#endif

#define ocf_metadata_bit_funcs(type) \
ocf_metadata_bit_func(dirty, type); \
ocf_metadata_bit_func(valid, type); \
ocf_metadata_bit_func_basic(type)

#ifdef OCF_BLOCK_SIZE_4K
ocf_metadata_bit_funcs_no_type();
#endif
ocf_metadata_bit_funcs(u8);
ocf_metadata_bit_funcs(u16);
#ifndef OCF_BLOCK_SIZE_4K
ocf_metadata_bit_funcs(u32);
ocf_metadata_bit_funcs(u64);
ocf_metadata_bit_funcs(u128);
#endif

/*******************************************************************************
 * Status operations dispatched by cache line size
 ******************************************************************************/

#ifdef OCF_BLOCK_SIZE_4K
#define _ocf_metadata_bit_dispatch(line_size, func, ...) \
	switch (line_size) { \
	case ocf_cache_line_size_4: \
		return func(__VA_ARGS__); \
	case ocf_cache_line_size_8: \
	case ocf_cache_line_size_16: \
	case ocf_cache_line_size_32: \
		return func##_u8(__VA_ARGS__); \
	case ocf_cache_line_size_64: \
		return func##_u16(__VA_ARGS__); \
	case ocf_cache_line_size_none: \
	default: \
		ENV_BUG(); \
	}
#else
#define _ocf_metadata_bit_dispatch(line_size, func, ...) \
	switch (line_size) { \
	case ocf_cache_line_size_4: \
		return func##_u8(__VA_ARGS__); \
	case ocf_cache_line_size_8: \
		return func##_u16(__VA_ARGS__); \
	case ocf_cache_line_size_16: \
		return func##_u32(__VA_ARGS__); \
	case ocf_cache_line_size_32: \
		return func##_u64(__VA_ARGS__); \
	case ocf_cache_line_size_64: \
		return func##_u128(__VA_ARGS__); \
	case ocf_cache_line_size_none: \
	default: \
		ENV_BUG(); \
	}
#endif

#define _ocf_metadata_bit_funcs_5arg(what) \
static inline bool ocf_metadata_bit_##what( \
		struct ocf_metadata_map *entry, \
		ocf_cache_line_size_t line_size, \
		uint8_t start, uint8_t stop, bool all) \
{ \
	_ocf_metadata_bit_dispatch(line_size, _ocf_metadata_##what, \
			entry, start, stop, all); \
	return false; \
}

#define _ocf_metadata_bit_funcs_4arg(what) \
static inline bool ocf_metadata_bit_##what( \
		struct ocf_metadata_map *entry, \
		ocf_cache_line_size_t line_size, \
		uint8_t start, uint8_t stop) \
{ \
	_ocf_metadata_bit_dispatch(line_size, _ocf_metadata_##what, \
			entry, start, stop); \
	return false; \
}

#define _ocf_metadata_bit_funcs(what) \
	_ocf_metadata_bit_funcs_5arg(test_##what) \
	_ocf_metadata_bit_funcs_4arg(test_out_##what) \
	_ocf_metadata_bit_funcs_4arg(clear_##what) \
	_ocf_metadata_bit_funcs_4arg(set_##what) \
	_ocf_metadata_bit_funcs_5arg(test_and_set_##what) \
	_ocf_metadata_bit_funcs_5arg(test_and_clear_##what)

_ocf_metadata_bit_funcs(dirty)
_ocf_metadata_bit_funcs(valid)

_ocf_metadata_bit_funcs_4arg(clear_valid_if_clean)

static inline void ocf_metadata_bit_clear_dirty_if_invalid(
		struct ocf_metadata_map *entry, ocf_cache_line_size_t line_size,
		uint8_t start, uint8_t stop)
{
	_ocf_metadata_bit_dispatch(line_size,
			_ocf_metadata_clear_dirty_if_invalid,
			entry, start, stop);
}

static inline bool ocf_metadata_bit_check(
		const struct ocf_metadata_map *entry,
		ocf_cache_line_size_t line_size)
{
	_ocf_metadata_bit_dispatch(line_size, _ocf_metadata_check, entry);
	return false;
}

#endif /* __METADATA_BIT_H__ */
