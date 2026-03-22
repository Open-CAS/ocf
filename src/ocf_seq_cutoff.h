/*
 * Copyright(c) 2020-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_SEQ_CUTOFF_H__
#define __OCF_SEQ_CUTOFF_H__

#include "ocf/ocf.h"
#include "ocf_request.h"
#include "ocf_seq_detect.h"

void ocf_core_seq_cutoff_init(ocf_core_t core);
void ocf_core_seq_cutoff_deinit(ocf_core_t core);
void ocf_seq_cutoff_set_policy(ocf_core_t core,
		ocf_seq_cutoff_policy policy);

bool ocf_core_seq_cutoff_check(ocf_core_t core, struct ocf_request *req);

#endif /* __OCF_SEQ_CUTOFF_H__ */
