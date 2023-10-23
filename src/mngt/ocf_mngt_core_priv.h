/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_MNGT_CORE_PRIV_H__
#define __OCF_MNGT_CORE_PRIV_H__

#include "../ocf_core_priv.h"

int ocf_mngt_core_init_front_volume(ocf_core_t core);

void ocf_mngt_core_clear_uuid_metadata(ocf_core_t core);

ocf_seq_no_t ocf_mngt_get_core_seq_no(ocf_cache_t cache);

#endif /* __OCF_MNGT_CORE_PRIV_H__ */
