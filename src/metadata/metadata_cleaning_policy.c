/*
 * Copyright(c) 2020-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "metadata.h"
#include "metadata_cleaning_policy.h"
#include "metadata_internal.h"

/*
 * Cleaning policy - Get
 */
struct cleaning_policy_meta *
ocf_metadata_get_cleaning_policy(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	struct ocf_metadata_ctrl *ctrl
		= (struct ocf_metadata_ctrl *) cache->metadata.priv;

	ENV_BUG_ON(cache->conf_meta->cleaner_disabled);

	return ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_cleaning]), line);
}
