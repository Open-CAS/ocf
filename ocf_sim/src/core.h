/*
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _CORE_H_
#define	_CORE_H_

#include <stdint.h>

#include "ocf/ocf_types.h"

typedef struct core_handle_s *core_handle_t;

int core_add_all(ocf_cache_t cache);
void core_cleanup(void);
ocf_core_t core_get_core(core_handle_t handle);
core_handle_t core_get_handle(int16_t mj, int32_t mi);
core_handle_t core_get_next(core_handle_t handle);
uint64_t core_get_size(core_handle_t handle);
long core_get_q_idx(core_handle_t handle, uint64_t sector);
void core_init(char *swap_info_file);
core_handle_t core_new(int16_t mj, int32_t mi);
long core_set_q_idx(core_handle_t handle, uint64_t sector, long idx);

#endif
