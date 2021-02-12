/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __UTILS_ALLOCATOR_H__
#define __UTILS_ALLOCATOR_H__

#include "ocf_env.h"

#define OCF_LOG_ALLOCATOR_NAME_MAX 64

struct ocf_log_allocator;

struct ocf_log_allocator* ocf_log_allocator_init(char* name_fmt, uint32_t count,
	size_t (*size_of)(uint32_t));

void ocf_log_allocator_deinit(struct ocf_log_allocator *allocator);

env_allocator *ocf_log_allocator_get(struct ocf_log_allocator *allocator,
	uint32_t count);

env_allocator *ocf_log_allocator_get_1(struct ocf_log_allocator *allocator);

#endif /* __UTILS_ALLOCATOR_H__ */
