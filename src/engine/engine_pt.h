/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ENGINE_OFF_H_
#define ENGINE_OFF_H_

int ocf_read_pt(struct ocf_request *req);

int ocf_read_pt_do(struct ocf_request *req);

void ocf_queue_push_req_pt(struct ocf_request *req);

#endif /* ENGINE_OFF_H_ */
