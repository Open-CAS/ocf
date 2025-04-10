/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ENGINE_RD_H_
#define ENGINE_RD_H_

int ocf_read_generic(struct ocf_request *req);

void ocf_read_generic_submit_hit(struct ocf_request *req);
bool ocf_read_generic_fast(struct ocf_request *req);

#endif /* ENGINE_RD_H_ */
