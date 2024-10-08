/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_DEBUG_H__
#define __OCF_DEBUG_H__

struct ocf_dbg_seq_cutoff_status {
	struct {
		uint64_t last;
		uint64_t bytes;
		uint32_t rw : 1;
		uint32_t active : 1;
	} streams[OCF_SEQ_CUTOFF_PERCORE_STREAMS];
};

void ocf_dbg_get_seq_cutoff_status(ocf_core_t core,
		struct ocf_dbg_seq_cutoff_status *status);

bool ocf_dbg_cache_is_settled(ocf_cache_t cache);

#endif /* __OCF_DEBUG_H__ */
