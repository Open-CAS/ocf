/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __CLEANING_H__
#define __CLEANING_H__

#include "../metadata/metadata_cleaning_policy.h"
#include "ocf_env_refcnt.h"
#include "ocf/ocf_cleaner.h"

#define SLEEP_TIME_MS (1000)

struct ocf_request;

struct ocf_cleaner {
	struct env_refcnt refcnt;
	ocf_cleaning_t policy;
	void *cleaning_policy_context;
	ocf_queue_t io_queue;
	ocf_cleaner_end_t end;
	void *priv;
};

int ocf_start_cleaner(ocf_cache_t cache);

void ocf_kick_cleaner(ocf_cache_t cache);

void ocf_stop_cleaner(ocf_cache_t cache);

typedef void (*ocf_cleaning_op_end_t)(void *priv, int error);

#endif /* __CLEANING_H__ */
