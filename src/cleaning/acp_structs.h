/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __CLEANING_AGGRESSIVE_STRUCTS_H__
#define __CLEANING_AGGRESSIVE_STRUCTS_H__

#include "ocf_env_headers.h"

/* TODO: remove acp metadata */
struct acp_cleaning_policy_meta {
	uint8_t dirty : 1;
};

/* cleaning policy per partition metadata */
struct acp_cleaning_policy_config {
	uint32_t thread_wakeup_time;	/* in milliseconds*/
	uint32_t flush_max_buffers;	/* in lines */
};

#endif


