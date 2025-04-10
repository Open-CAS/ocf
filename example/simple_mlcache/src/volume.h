/*
 * Copyright(c) 2019-2021 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __VOLUME_H__
#define __VOLUME_H__

#include <ocf/ocf.h>
#include "ocf_env.h"
#include "ctx.h"
#include "data.h"

struct myvolume {
	uint8_t *mem;
	const char *name;
};

int volume_init(ocf_ctx_t ocf_ctx);
void volume_cleanup(ocf_ctx_t ocf_ctx);

#endif
