/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_PARTITION_H__
#define __METADATA_PARTITION_H__

#include "metadata_partition_structs.h"
#include "../ocf_cache_priv.h"

#define PARTITION_DEFAULT		0
#define PARTITION_INVALID		((ocf_part_id_t)-1)
#define PARTITION_SIZE_MAX		((ocf_cache_line_t)-1)

static inline void ocf_metadata_get_partition_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_part_id_t *part_id, ocf_cache_line_t *next_line,
		ocf_cache_line_t *prev_line)
{
	cache->metadata.iface.get_partition_info(cache, line, part_id,
			next_line, prev_line);
}

static inline ocf_part_id_t ocf_metadata_get_partition_id(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	ocf_part_id_t part_id;

	ocf_metadata_get_partition_info(cache, line, &part_id, NULL, NULL);

	return part_id;
}

static inline ocf_cache_line_t ocf_metadata_get_partition_next(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	ocf_cache_line_t next;

	ocf_metadata_get_partition_info(cache, line, NULL, &next, NULL);

	return next;
}

static inline ocf_cache_line_t ocf_metadata_get_partition_prev(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	ocf_cache_line_t prev;

	ocf_metadata_get_partition_info(cache, line, NULL, NULL, &prev);

	return prev;
}

static inline void ocf_metadata_set_partition_next(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next_line)
{
	cache->metadata.iface.set_partition_next(cache, line, next_line);
}

static inline void ocf_metadata_set_partition_prev(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t prev_line)
{
	cache->metadata.iface.set_partition_prev(cache, line, prev_line);
}

static inline void ocf_metadata_set_partition_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_part_id_t part_id, ocf_cache_line_t next_line,
		ocf_cache_line_t prev_line)
{
	cache->metadata.iface.set_partition_info(cache, line, part_id,
			next_line, prev_line);
}

void ocf_metadata_add_to_partition(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_cache_line_t line);

void ocf_metadata_remove_from_partition(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_cache_line_t line);

#endif /* __METADATA_PARTITION_H__ */
