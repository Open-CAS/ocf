/*
 * Copyright(c) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_SEGMENT_OPS_H__
#define __METADATA_SEGMENT_OPS_H__

#include "metadata_raw.h"
#include <ocf/ocf_def.h>

void ocf_metadata_check_crc_if_clean(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg);

void ocf_metadata_check_crc(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg);

void ocf_metadata_calculate_crc(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg);

void ocf_metadata_flush_segment(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg);

void ocf_metadata_load_segment(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg);

#endif
