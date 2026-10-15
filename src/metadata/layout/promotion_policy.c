/*
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "promotion_policy.h"

void ocf_nhit_promotion_policy_config_validate(
		const struct nhit_promotion_policy_config *config,
		struct nhit_promotion_policy_config_validity *valid)
{
	env_memset(valid, sizeof(*valid), 0);

	valid->insertion_threshold =
		config->insertion_threshold >= OCF_NHIT_MIN_THRESHOLD &&
		config->insertion_threshold <= OCF_NHIT_MAX_THRESHOLD;

	valid->trigger_threshold =
		config->trigger_threshold >= OCF_NHIT_MIN_TRIGGER &&
		config->trigger_threshold <= OCF_NHIT_MAX_TRIGGER;
}
