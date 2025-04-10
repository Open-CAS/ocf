/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_EVICT_COUNTERS_H__
#define __OCF_EVICT_COUNTERS_H__

#include "ocf_env.h"
#include "ocf/ocf_def.h"
#include "ocf/ocf_types.h"

void ocf_evict_counters_update(ocf_cache_t cache, uint16_t priority);

/* increment counter, and return its new value */
int32_t ocf_evict_counters_inc(ocf_cache_t cache, ocf_part_id_t part_id,
	int32_t delta);

#endif /* __OCF_EVICT_COUNTERS_H__ */
