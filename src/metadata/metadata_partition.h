/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies Co., Ltd.
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_PARTITION_H__
#define __METADATA_PARTITION_H__

#include "ocf/ocf.h"
#include "layout/partition.h"

ocf_part_id_t ocf_metadata_get_partition_id(struct ocf_cache *cache,
		ocf_cache_line_t line);

void ocf_metadata_set_partition_id(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_part_id_t part_id);

#endif /* __METADATA_PARTITION_H__ */
