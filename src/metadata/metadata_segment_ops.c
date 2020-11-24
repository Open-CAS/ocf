/*
 * Copyright(c) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "metadata_internal.h"
#include "metadata_superblock.h"

static void ocf_metadata_generic_complete(void *priv, int error)
{
	struct ocf_metadata_context *context = priv;

	OCF_PL_NEXT_ON_SUCCESS_RET(context->pipeline, error);
}

static void ocf_metadata_check_crc_skip(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg, bool skip_on_dirty_shutdown)
{
	struct ocf_metadata_context *context = priv;
	int segment = ocf_pipeline_arg_get_int(arg);
	struct ocf_metadata_ctrl *ctrl;
	struct ocf_superblock_config *sb_config;
	ocf_cache_t cache = context->cache;
	uint32_t crc;

	ctrl = (struct ocf_metadata_ctrl *)cache->metadata.priv;
	sb_config = METADATA_MEM_POOL(ctrl, metadata_segment_sb_config);

	if (!sb_config->clean_shutdown && skip_on_dirty_shutdown)
		OCF_PL_NEXT_RET(pipeline);

	crc = ocf_metadata_raw_checksum(cache, &(ctrl->raw_desc[segment]));

	if (crc != sb_config->checksum[segment]) {
		/* Checksum does not match */
		if (!sb_config->clean_shutdown) {
			ocf_cache_log(cache, log_warn,
					"Loading %s WARNING, invalid checksum",
					ocf_metadata_segment_names[segment]);
		} else {
			ocf_cache_log(cache, log_err,
					"Loading %s ERROR, invalid checksum",
					ocf_metadata_segment_names[segment]);
			OCF_PL_FINISH_RET(pipeline, -OCF_ERR_INVAL);
		}
	}

	ocf_pipeline_next(pipeline);
}

void ocf_metadata_check_crc(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	ocf_metadata_check_crc_skip(pipeline, priv, arg, false);
}

void ocf_metadata_check_crc_if_clean(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	ocf_metadata_check_crc_skip(pipeline, priv, arg, true);
}


void ocf_metadata_calculate_crc(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_context *context = priv;
	int segment = ocf_pipeline_arg_get_int(arg);
	struct ocf_metadata_ctrl *ctrl;
	struct ocf_superblock_config *sb_config;
	ocf_cache_t cache = context->cache;

	ctrl = (struct ocf_metadata_ctrl *)cache->metadata.priv;
	sb_config = METADATA_MEM_POOL(ctrl, metadata_segment_sb_config);

	sb_config->checksum[segment] = ocf_metadata_raw_checksum(cache,
			&(ctrl->raw_desc[segment]));

	ocf_pipeline_next(pipeline);
}

void ocf_metadata_flush_segment(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_context *context = priv;
	int segment = ocf_pipeline_arg_get_int(arg);
	struct ocf_metadata_ctrl *ctrl;
	ocf_cache_t cache = context->cache;

	ctrl = (struct ocf_metadata_ctrl *)cache->metadata.priv;

	ocf_metadata_raw_flush_all(cache, &ctrl->raw_desc[segment],
			ocf_metadata_generic_complete, context);
}

void ocf_metadata_load_segment(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
	struct ocf_metadata_context *context = priv;
	int segment = ocf_pipeline_arg_get_int(arg);
	struct ocf_metadata_ctrl *ctrl;
	ocf_cache_t cache = context->cache;

	ctrl = (struct ocf_metadata_ctrl *)cache->metadata.priv;

	ocf_metadata_raw_load_all(cache, &ctrl->raw_desc[segment],
			ocf_metadata_generic_complete, context);
}
