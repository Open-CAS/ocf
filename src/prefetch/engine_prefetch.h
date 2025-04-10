/*
 * Copyright(c) 2023 Huawei Technologies Co., Ltd
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ENGINE_PREFETCH_H_
#define ENGINE_PREFETCH_H_

#include "../ocf_request.h"

int ocf_prefetch_read(struct ocf_request *req);

#endif /* ENGINE_PREFETCH_H_ */
