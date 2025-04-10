/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "ocf_metadata_algid.h"
#include "../metadata/metadata.h"
#include "../metadata/metadata_internal.h"

pf_algo_id_t ocf_metadata_get_algorithm_id(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	const struct ocf_metadata_list_info *info;
	struct ocf_metadata_ctrl *ctrl =
		(struct ocf_metadata_ctrl *) cache->metadata.priv;

	info = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line);

	ENV_BUG_ON(!info);

	return info->pf_alg_id;
}

void ocf_metadata_set_algorithm_id(struct ocf_cache *cache,
		ocf_cache_line_t line, pf_algo_id_t pf_alg_id)
{
	struct ocf_metadata_list_info *info;
	struct ocf_metadata_ctrl *ctrl =
		(struct ocf_metadata_ctrl *) cache->metadata.priv;

	info = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line);

	if (info)
		info->pf_alg_id = pf_alg_id;
	else
		ocf_metadata_error(cache);
}
