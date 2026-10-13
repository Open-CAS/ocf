/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_CLEANING_POLICY_H__
#define __METADATA_CLEANING_POLICY_H__

#include "ocf/ocf.h"
#include "layout/cleaning_policy.h"

struct cleaning_policy_meta *
ocf_metadata_get_cleaning_policy(struct ocf_cache *cache,
		ocf_cache_line_t line);

#endif /* __METADATA_CLEANING_POLICY_H__ */
