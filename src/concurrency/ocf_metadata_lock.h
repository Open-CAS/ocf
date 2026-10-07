/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2025 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_METADATA_LOCK_H__
#define __OCF_METADATA_LOCK_H__

#include "ocf/ocf.h"
#include "ocf_env.h"
#include "../metadata/metadata_lru.h"

#define OCF_METADATA_GLOBAL_LOCK_IDX_BITS 2
#define OCF_NUM_GLOBAL_META_LOCKS (1 << (OCF_METADATA_GLOBAL_LOCK_IDX_BITS))

struct ocf_metadata_global_lock {
	env_rwsem sem;
} __attribute__((aligned(64)));

struct ocf_metadata_lock {
	struct ocf_metadata_global_lock global[OCF_NUM_GLOBAL_META_LOCKS];
			/*!< global metadata lock (GML) */
	env_spinlock lru[OCF_NUM_LRU_LISTS]; /*!< Fast locks for lru list */
	env_spinlock partition[OCF_USER_IO_CLASS_MAX]; /* partition lock */
	ocf_cache_t cache;  /*!< Parent cache object */
	uint32_t num_hash_entries;  /*!< Hash bucket count */
};

#endif /* __OCF_METADATA_LOCK_H__ */
