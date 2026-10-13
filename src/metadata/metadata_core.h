/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_CORE_H__
#define __METADATA_CORE_H__

#include "ocf/ocf.h"
#include "layout/core.h"

struct ocf_metadata_uuid *ocf_metadata_get_core_uuid(
		struct ocf_cache *cache, ocf_core_id_t core_id);

void ocf_metadata_get_core_and_part_id(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_core_id_t *core_id, ocf_part_id_t *part_id);

#endif /* __METADATA_CORE_H__ */
