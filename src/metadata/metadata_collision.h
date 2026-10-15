/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2022-2023 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_COLLISION_H__
#define __METADATA_COLLISION_H__

#include "ocf/ocf.h"
#include "layout/collision.h"

void ocf_metadata_set_collision_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next, ocf_cache_line_t prev);

void ocf_metadata_set_collision_next(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next);

void ocf_metadata_set_collision_prev(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t prev);

struct ocf_metadata_map *ocf_metadata_get_collision(
		struct ocf_cache *cache, ocf_cache_line_t line);

void ocf_metadata_get_core_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_core_id_t *core_id,
		uint64_t *core_line);

void ocf_metadata_set_core_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_core_id_t core_id,
		uint64_t core_line);

ocf_core_id_t ocf_metadata_get_core_id(
		struct ocf_cache *cache, ocf_cache_line_t line);

void ocf_metadata_get_collision_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t *next, ocf_cache_line_t *prev);

static inline ocf_cache_line_t ocf_metadata_get_collision_next(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	ocf_cache_line_t next;

	ocf_metadata_get_collision_info(cache, line, &next, NULL);
	return next;
}

static inline ocf_cache_line_t ocf_metadata_get_collision_prev(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	ocf_cache_line_t prev;

	ocf_metadata_get_collision_info(cache, line, NULL, &prev);
	return prev;
}

void ocf_metadata_add_to_collision(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t core_line,
		ocf_cache_line_t hash, ocf_cache_line_t cache_line);

void ocf_metadata_remove_from_collision(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t part_id);

void ocf_metadata_start_collision_shared_access(
		struct ocf_cache *cache, ocf_cache_line_t line);

void ocf_metadata_end_collision_shared_access(
		struct ocf_cache *cache, ocf_cache_line_t line);

#endif /* __METADATA_COLLISION_H__ */
