/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __VOLUME_H__
#define __VOLUME_H__

#include <ocf/ocf.h>
#include <ocf/ocf_blktrace.h>

#include "ctx.h"
#include "data.h"

#define VOLUME_TYPE	1

int volume_init(ocf_ctx_t ocf_ctx);
void volume_cleanup(ocf_ctx_t ocf_ctx);
void volume_complete_io(ocf_io_t *ocf_io);

#endif
