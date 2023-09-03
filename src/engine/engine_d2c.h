/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ENGINE_2DC_H_
#define ENGINE_2DC_H_

int ocf_d2c_io(struct ocf_request *req);

int ocf_d2c_flush(struct ocf_request *req);

int ocf_d2c_discard(struct ocf_request *req);

#endif /* ENGINE_2DC_H_ */
