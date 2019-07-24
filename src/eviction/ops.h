/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef LAYER_EVICTION_POLICY_OPS_H_
#define LAYER_EVICTION_POLICY_OPS_H_

#include "eviction.h"
#include "../metadata/metadata.h"
#include "../concurrency/ocf_metadata_concurrency.h"

/**
 * @brief Initialize cache line before adding it into eviction
 *
 * @note This operation is called under WR metadata lock
 */
static inline void ocf_eviction_init_cache_line(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t part_id)
{
	uint8_t type;

	type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(type >= ocf_eviction_max);

	if (likely(evict_policy_ops[type].init_cline))
		evict_policy_ops[type].init_cline(cache, line);
}

static inline void ocf_eviction_purge_cache_line(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	uint8_t type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(type >= ocf_eviction_max);

	if (likely(evict_policy_ops[type].rm_cline)) {
		OCF_METADATA_EVICTION_LOCK();
		evict_policy_ops[type].rm_cline(cache, line);
		OCF_METADATA_EVICTION_UNLOCK();
	}
}


static inline bool ocf_eviction_can_evict(struct ocf_cache *cache)
{
	uint8_t type = cache->conf_meta->eviction_policy_type;

	if (likely(evict_policy_ops[type].can_evict))
		return evict_policy_ops[type].can_evict(cache);

	return true;
}

static inline uint32_t ocf_eviction_need_space(struct ocf_cache *cache,
		ocf_queue_t io_queue, ocf_part_id_t part_id, uint32_t clines)
{
	uint8_t type;
	uint32_t result = 0;

	type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(type >= ocf_eviction_max);

	if (likely(evict_policy_ops[type].req_clines)) {
		/*
		 * This is called under METADATA WR lock. No need to get
		 * eviction lock.
		 */
		result = evict_policy_ops[type].req_clines(cache, io_queue,
				part_id, clines);
	}

	return result;
}

static inline void ocf_eviction_set_hot_cache_line(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	uint8_t type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(type >= ocf_eviction_max);

	if (likely(evict_policy_ops[type].hot_cline)) {
		OCF_METADATA_EVICTION_LOCK();
		evict_policy_ops[type].hot_cline(cache, line);
		OCF_METADATA_EVICTION_UNLOCK();
	}
}

static inline void ocf_eviction_initialize(struct ocf_cache *cache,
		ocf_part_id_t part_id)
{
	uint8_t type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(type >= ocf_eviction_max);

	if (likely(evict_policy_ops[type].init_evp)) {
		OCF_METADATA_EVICTION_LOCK();
		evict_policy_ops[type].init_evp(cache, part_id);
		OCF_METADATA_EVICTION_UNLOCK();
	}
}

#endif /* LAYER_EVICTION_POLICY_OPS_H_ */
