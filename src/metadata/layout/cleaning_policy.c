/*
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cleaning_policy.h"

void ocf_alru_cleaning_policy_config_validate(
		const struct alru_cleaning_policy_config *config,
		struct alru_cleaning_policy_config_validity *valid)
{
	env_memset(valid, sizeof(*valid), 0);

	valid->thread_wakeup_time =
		config->thread_wakeup_time >= OCF_ALRU_MIN_WAKE_UP &&
		config->thread_wakeup_time <= OCF_ALRU_MAX_WAKE_UP;

	valid->stale_buffer_time =
		config->stale_buffer_time >= OCF_ALRU_MIN_STALENESS_TIME &&
		config->stale_buffer_time <= OCF_ALRU_MAX_STALENESS_TIME;

	valid->flush_max_buffers =
		config->flush_max_buffers >= OCF_ALRU_MIN_FLUSH_MAX_BUFFERS &&
		config->flush_max_buffers <= OCF_ALRU_MAX_FLUSH_MAX_BUFFERS;

	valid->activity_threshold =
		config->activity_threshold >=
				OCF_ALRU_MIN_ACTIVITY_THRESHOLD &&
		config->activity_threshold <=
				OCF_ALRU_MAX_ACTIVITY_THRESHOLD;

	valid->dirty_ratio_threshold =
		config->dirty_ratio_threshold >=
				OCF_ALRU_MIN_DIRTY_RATIO_THRESHOLD &&
		config->dirty_ratio_threshold <=
				OCF_ALRU_MAX_DIRTY_RATIO_THRESHOLD;
}

void ocf_acp_cleaning_policy_config_validate(
		const struct acp_cleaning_policy_config *config,
		struct acp_cleaning_policy_config_validity *valid)
{
	env_memset(valid, sizeof(*valid), 0);

	valid->thread_wakeup_time =
		config->thread_wakeup_time >= OCF_ACP_MIN_WAKE_UP &&
		config->thread_wakeup_time <= OCF_ACP_MAX_WAKE_UP;

	valid->flush_max_buffers =
		config->flush_max_buffers >= OCF_ACP_MIN_FLUSH_MAX_BUFFERS &&
		config->flush_max_buffers <= OCF_ACP_MAX_FLUSH_MAX_BUFFERS;
}
