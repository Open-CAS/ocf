/*
 * Copyright(c) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_SEQ_CUTOFF_H__
#define __OCF_SEQ_CUTOFF_H__

#include "ocf/ocf.h"
#include "ocf_request.h"
#include "utils/utils_rbtree.h"

struct ocf_seq_cutoff_stream {
	uint64_t last;
	uint64_t bytes;
	uint32_t rw : 1;
	struct ocf_rb_node node;
	struct list_head list;
};

struct ocf_seq_cutoff {
	ocf_core_t core;
	env_rwlock lock;
	struct ocf_seq_cutoff_stream streams[OCF_SEQ_CUTOFF_MAX_STREAMS];
	struct ocf_rb_tree tree;
	struct list_head lru;
};

int ocf_core_seq_cutoff_init(ocf_core_t core);

void ocf_core_seq_cutoff_deinit(ocf_core_t core);

bool ocf_core_seq_cutoff_check(ocf_core_t core, struct ocf_request *req);

void ocf_core_seq_cutoff_update(ocf_core_t core, struct ocf_request *req);

#endif /* __OCF_SEQ_CUTOFF_H__ */
