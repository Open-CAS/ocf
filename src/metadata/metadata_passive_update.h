/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_METADATA_PASSIVE_IO_H__
#define __OCF_METADATA_PASSIVE_IO_H__

int ocf_metadata_passive_update(struct ocf_request *master);

int ocf_metadata_passive_io_ctx_init(ocf_cache_t cache);

void ocf_metadata_passive_io_ctx_deinit(ocf_cache_t cache);

#endif
