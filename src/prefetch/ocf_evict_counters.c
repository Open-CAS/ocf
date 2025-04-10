/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "../ocf_cache_priv.h"
#include "../utils/utils_user_part.h"
#include "ocf_evict_counters.h"

#define MIN_EVICT_QUOTA 256

static inline env_atomic *_evict_counter(ocf_cache_t cache, ocf_part_id_t i)
{
	return &cache->user_parts[i].part.runtime->evict_counter;
}

void ocf_evict_counters_update(ocf_cache_t cache, uint16_t priority)
{
	struct ocf_user_part *user_part;
	ocf_part_id_t part_id;
	ocf_part_id_t i;
	ocf_cache_line_t part_sizes[OCF_USER_IO_CLASS_MAX];
	uint64_t part_size, least_part_size;

	least_part_size = ocf_metadata_get_cachelines_count(cache);
	i = 0;
	for_each_user_part(cache, user_part, part_id) {
		if (priority > user_part->config->priority)
			break;
		part_size = part_sizes[i++] =
			env_atomic_read(&user_part->part.runtime->curr_size);
		if (part_size == 0)
			continue;
		least_part_size = OCF_MIN(least_part_size, part_size);
	}
	least_part_size = OCF_MAX(least_part_size, MIN_EVICT_QUOTA);
	i = 0;
	for_each_user_part(cache, user_part, part_id) {
		if (priority > user_part->config->priority)
			break;
		part_size = part_sizes[i++];
		if (part_size == 0)
			continue;
		env_atomic_add(part_size * MIN_EVICT_QUOTA / least_part_size,
			_evict_counter(cache, part_id));
	}
}

/* increment counter, and return its new value */
int32_t ocf_evict_counters_inc(ocf_cache_t cache, ocf_part_id_t part_id,
		int32_t delta)
{
	return env_atomic_add_return(delta, _evict_counter(cache, part_id));
}
