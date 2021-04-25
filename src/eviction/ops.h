/*
 * Copyright(c) 2012-2021 Intel Corporation
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
		ocf_cache_line_t line)
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
		OCF_METADATA_EVICTION_WR_LOCK(line);
		evict_policy_ops[type].rm_cline(cache, line);
		OCF_METADATA_EVICTION_WR_UNLOCK(line);
	}
}

static inline bool ocf_eviction_can_evict(struct ocf_cache *cache)
{
	uint8_t type = cache->conf_meta->eviction_policy_type;

	if (likely(evict_policy_ops[type].can_evict))
		return evict_policy_ops[type].can_evict(cache);

	return true;
}

static inline uint32_t ocf_eviction_need_space(ocf_cache_t cache,
		struct ocf_request *req, struct ocf_part *part,
		uint32_t clines)
{
	uint8_t type;
	uint32_t result = 0;

	type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(type >= ocf_eviction_max);

	if (likely(evict_policy_ops[type].req_clines))
		result = evict_policy_ops[type].req_clines(req, part, clines);

	return result;
}

static inline void ocf_eviction_set_hot_cache_line(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	uint8_t type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(type >= ocf_eviction_max);

	if (likely(evict_policy_ops[type].hot_cline)) {
		evict_policy_ops[type].hot_cline(cache, line);
	}
}

static inline void ocf_eviction_initialize(struct ocf_cache *cache,
		struct ocf_part *part)
{
	uint8_t type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(type >= ocf_eviction_max);

	if (likely(evict_policy_ops[type].init_evp)) {
		evict_policy_ops[type].init_evp(cache, part);
	}
}

static inline void ocf_eviction_flush_dirty(ocf_cache_t cache,
		struct ocf_user_part *user_part, ocf_queue_t io_queue,
		uint32_t count)
{
	uint8_t type = cache->conf_meta->eviction_policy_type;

	ENV_BUG_ON(type >= ocf_eviction_max);

	if (likely(evict_policy_ops[type].flush_dirty)) {
		evict_policy_ops[type].flush_dirty(cache, user_part, io_queue,
				count);
	}
}

#endif /* LAYER_EVICTION_POLICY_OPS_H_ */
