/*
 * Copyright(c) 2020-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_SEQ_DETECT_H__
#define __OCF_SEQ_DETECT_H__

#include "ocf/ocf.h"
#include "ocf_request.h"
#include "utils/utils_rbtree.h"

#define OCF_SEQ_DETECT_PERCORE_STREAMS 128
#define OCF_SEQ_DETECT_PERQUEUE_STREAMS 64

struct ocf_seq_detect_stream {
	uint64_t last;
	uint64_t bytes;
	uint32_t rw : 1;
	uint32_t valid : 1;
	uint32_t req_count : 16;
	struct ocf_rb_node node;
	struct list_head list;
};

struct ocf_seq_detect {
	env_rwlock lock;
	struct ocf_rb_tree tree;
	struct list_head lru;
	uint32_t promotion_count;
	uint32_t promotion_threshold;
	env_atomic consumer_count;
	struct ocf_seq_detect_stream streams[];
};

struct ocf_seq_detect_percore {
	struct ocf_seq_detect base;
	struct ocf_seq_detect_stream streams[OCF_SEQ_DETECT_PERCORE_STREAMS];
};

struct ocf_seq_detect_perqueue {
	struct ocf_seq_detect base;
	struct ocf_seq_detect_stream streams[OCF_SEQ_DETECT_PERQUEUE_STREAMS];
};


int ocf_core_seq_detect_init(ocf_core_t core);

void ocf_core_seq_detect_deinit(ocf_core_t core);

int ocf_queue_seq_detect_init(ocf_queue_t queue);

void ocf_queue_seq_detect_deinit(ocf_queue_t queue);

/**
 * @brief Register a consumer of this detector
 *
 * When consumer count is > 0, the detector update runs in the I/O path.
 */
void ocf_seq_detect_register_consumer(struct ocf_seq_detect *sd);

/**
 * @brief Unregister a consumer of this detector
 */
void ocf_seq_detect_unregister_consumer(struct ocf_seq_detect *sd);

/**
 * @brief Update streams based on request
 */
void ocf_core_seq_detect_update(ocf_core_t core, struct ocf_request *req);

/**
 * @brief Find a stream matching given address and direction
 *
 * Caller must hold sd->lock (at least read).
 *
 * @return stream pointer if found, NULL otherwise
 */
struct ocf_seq_detect_stream *ocf_seq_detect_find(
		struct ocf_seq_detect *sd, uint64_t addr, int rw);

#endif /* __OCF_SEQ_DETECT_H__ */
