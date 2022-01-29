/*
 * Copyright(c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __UTILS_GENERATOR_H__
#define __UTILS_GENERATOR_H__

#include "ocf/ocf.h"

struct ocf_generator_bisect_state {
	uint32_t curr;
	uint32_t limit;
};

void ocf_generator_bisect_init(
		struct ocf_generator_bisect_state *generator,
		uint32_t limit, uint32_t offset);

uint32_t ocf_generator_bisect_next(
		struct ocf_generator_bisect_state *generator);

#endif /* __UTILS_GENERATOR_H__ */
