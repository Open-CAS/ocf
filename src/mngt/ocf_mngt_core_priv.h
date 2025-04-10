/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_MNGT_CORE_PRIV_H__
#define __OCF_MNGT_CORE_PRIV_H__

#include "../ocf_core_priv.h"

int ocf_mngt_core_init_front_volume(ocf_core_t core);

int ocf_mngt_core_init_prefetch(ocf_core_t core);

void ocf_mngt_core_clear_uuid_metadata(ocf_core_t core);

ocf_seq_no_t ocf_mngt_get_core_seq_no(ocf_cache_t cache);

typedef void (*ocf_mngt_core_min_io_size_detect_end_t)(void *priv, int error);

void ocf_mngt_core_min_io_size_detect(ocf_core_t core,
		ocf_mngt_core_min_io_size_detect_end_t cmpl, void *priv);

void ocf_mngt_cache_add_core_to_upper_cache(ocf_cache_t cache,
		ocf_core_t lower_core, ocf_mngt_cache_add_core_end_t cb,
		void *priv);


#endif /* __OCF_MNGT_CORE_PRIV_H__ */
