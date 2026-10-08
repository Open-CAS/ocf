/*
 * Copyright(c) 2020-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "metadata.h"
#include "metadata_core.h"
#include "metadata_internal.h"
#include "metadata_raw.h"

struct ocf_metadata_uuid *ocf_metadata_get_core_uuid(
		struct ocf_cache *cache, ocf_core_id_t core_id)
{
	struct ocf_metadata_uuid *muuid;
	struct ocf_metadata_ctrl *ctrl =
		(struct ocf_metadata_ctrl *) cache->metadata.priv;

	muuid = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_core_uuid]), core_id);

	if (!muuid)
		ocf_metadata_error(cache);

	return muuid;
}
