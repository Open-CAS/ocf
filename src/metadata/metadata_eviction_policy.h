/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_EVICTION_H__
#define __METADATA_EVICTION_H__

static inline void ocf_metadata_get_evicition_policy(
		struct ocf_cache *cache, ocf_cache_line_t line,
		union eviction_policy_meta *eviction)
{
	cache->metadata.iface.get_eviction_policy(cache, line, eviction);
}

/*
 * SET
 */
static inline void ocf_metadata_set_evicition_policy(
		struct ocf_cache *cache, ocf_cache_line_t line,
		union eviction_policy_meta *eviction)
{
	cache->metadata.iface.set_eviction_policy(cache, line, eviction);
}

#endif /* METADATA_EVICTION_H_ */
