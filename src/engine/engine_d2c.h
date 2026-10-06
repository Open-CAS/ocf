/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __ENGINE_D2C_H__
#define __ENGINE_D2C_H__

int ocf_d2c_io_fast(struct ocf_request *req);

int ocf_d2c_flush_fast(struct ocf_request *req);

int ocf_d2c_discard_fast(struct ocf_request *req);

#endif /* __ENGINE_D2C_H__ */
