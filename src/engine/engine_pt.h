/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __ENGINE_PT_H__
#define __ENGINE_PT_H__

int ocf_read_pt(struct ocf_request *req);

int ocf_read_pt_do(struct ocf_request *req);

void ocf_queue_push_req_pt(struct ocf_request *req);

#endif /* __ENGINE_PT_H__ */
