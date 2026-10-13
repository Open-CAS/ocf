/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2022-2023 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_LRU_H__
#define __METADATA_LRU_H__

#include "ocf/ocf.h"
#include "layout/lru.h"

struct ocf_lru_meta *
ocf_metadata_get_lru(
		struct ocf_cache *cache, ocf_cache_line_t line);

#endif /* __METADATA_LRU_H__ */
