/*
 * Copyright(c) 2022-2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_PREFETCH_POLICY_H__
#define __METADATA_PREFETCH_POLICY_H__

#include "ocf/ocf.h"
#include "ocf/ocf_prefetch.h"

/* Prefetch policy configuration (stored in superblock) */

#define PREFETCH_POLICY_CONFIG_BYTES 256
#define PREFETCH_POLICY_TYPE_MAX ((int)ocf_pf_num)

struct prefetch_policy_config {
	uint8_t data[PREFETCH_POLICY_CONFIG_BYTES];
} __attribute__((aligned(4)));

struct readahead_prefetch_policy_config {
	uint32_t threshold;	/* in bytes */
};

#endif /* __METADATA_PREFETCH_POLICY_H__ */
