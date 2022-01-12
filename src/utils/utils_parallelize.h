/*
 * Copyright(c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __UTILS_PARALLELIZE_H__
#define __UTILS_PARALLELIZE_H__

#include "ocf/ocf.h"

typedef struct ocf_parallelize *ocf_parallelize_t;

typedef int (*ocf_parallelize_handle_t)(ocf_parallelize_t parallelize,
		void *priv, unsigned shard_id, unsigned shards_cnt);

typedef void (*ocf_parallelize_finish_t)(ocf_parallelize_t parallelize,
		void *priv, int error);

int ocf_parallelize_create(ocf_parallelize_t *parallelize,
		ocf_cache_t cache, unsigned shards_cnt, uint32_t priv_size,
		ocf_parallelize_handle_t handle,
		ocf_parallelize_finish_t finish);

void ocf_parallelize_destroy(ocf_parallelize_t parallelize);

void ocf_parallelize_set_priv(ocf_parallelize_t parallelize, void *priv);

void *ocf_parallelize_get_priv(ocf_parallelize_t parallelize);

void ocf_parallelize_run(ocf_parallelize_t parallelize);

#endif /* __UTILS_PARALLELIZE_H__ */
