/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_LAYOUT_PROMOTION_POLICY_H__
#define __METADATA_LAYOUT_PROMOTION_POLICY_H__

#include "ocf/ocf.h"

/* Promotion policy configuration (stored in superblock) */

#define PROMOTION_POLICY_CONFIG_BYTES 256
#define PROMOTION_POLICY_TYPE_MAX 2

struct promotion_policy_config {
	uint8_t data[PROMOTION_POLICY_CONFIG_BYTES];
} __attribute__((aligned(4)));

struct nhit_promotion_policy_config {
	uint32_t insertion_threshold;
	/*!< Number of hits */

	uint32_t trigger_threshold;
	/*!< Cache occupancy (percentage value) */
};

/**
 * @brief Validity of NHIT promotion policy config fields
 */
struct nhit_promotion_policy_config_validity {
	bool insertion_threshold;
	bool trigger_threshold;
};

/**
 * @brief Validate NHIT promotion policy config
 *
 * @param config - NHIT promotion policy config
 * @param valid - Validity of NHIT promotion policy config fields
 */
void ocf_nhit_promotion_policy_config_validate(
		const struct nhit_promotion_policy_config *config,
		struct nhit_promotion_policy_config_validity *valid);

#endif /* __METADATA_LAYOUT_PROMOTION_POLICY_H__ */
