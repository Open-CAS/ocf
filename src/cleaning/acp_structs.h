/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __CLEANING_AGGRESSIVE_STRUCTS_H__
#define __CLEANING_AGGRESSIVE_STRUCTS_H__

#include "ocf_env_headers.h"

/* cleaning policy per partition metadata */
struct acp_cleaning_policy_config {
	uint32_t thread_wakeup_time;	/* in milliseconds*/
	uint32_t flush_max_buffers;	/* in lines */
};

#endif


