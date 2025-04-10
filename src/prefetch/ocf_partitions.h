/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __OCF_PARTITIONS_H__
#define __OCF_PARTITIONS_H__

#include "ocf/ocf_def.h"
#include "ocf/ocf_types.h"
#include "../ocf_cache_priv.h"

#define OCF_IO_CLASS_ID_SWAP		1
#define OCF_IO_CLASS_ID_PREFETCH	2

uint8_t ocf_partitions_get_io_class(ocf_io_t io, ocf_core_t core);
int ocf_partitions_config_predefined_partitions(ocf_cache_t cache);
int ocf_partitions_remove_predefined_partitions(ocf_cache_t cache);
void ocf_partitions_update_prefetch_max_size(ocf_cache_t cache);
void ocf_partitions_remove_swap_max_size_for_testing(ocf_cache_t cache);

#endif /* __OCF_PARTITIONS_H__ */
