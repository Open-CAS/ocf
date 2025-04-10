/*
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _CACHE_H_
#define	_CACHE_H_

#include <stdint.h>

#include "ocf/ocf_def.h"
#include "ocf/ocf_types.h"

#include "device.h"

#define CACHE_LOOP_ALL(_h)		\
		for (cache_handle_t _h = cache_get_next(NULL); _h; _h = cache_get_next(_h))

typedef struct _cache_s *cache_handle_t;

ocf_cache_t cache_add(int mcpus, ocf_ctx_t ctx, int num_comp_devices, ocf_cache_line_size_t cache_line_size,
			ocf_cache_mode_t cache_mode, device_type_t cache_type);
void cache_cleanup(void);
ocf_cache_t cache_get_cache(cache_handle_t handle);
ocf_core_t cache_get_core(cache_handle_t handle, int *core_id);
int cache_get_idx(cache_handle_t handle);
cache_handle_t cache_get_next(cache_handle_t handle);
ocf_queue_t cache_get_queue(ocf_cache_t cache, int cpu);
void cache_init(int cache_layers);
bool cache_is_composite(cache_handle_t handle);
void cache_kick_next_q(void);
void cache_remove(void);

#endif
