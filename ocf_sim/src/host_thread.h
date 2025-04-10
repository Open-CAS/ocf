/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef HOST_THREAD_H
#define HOST_THREAD_H

#include <stdbool.h>
#include <stdint.h>

#include "ocf_env.h"

#include "host_io.h"

typedef struct hostthread_handle_s *hostthread_handle_t;

void hostthread_cleanup(hostthread_handle_t *phandle);
bool hostthread_active(hostthread_handle_t handle);
void hostthread_trigger(hostthread_handle_t handle, int cpu);
void hostthread_start(hostthread_handle_t handle);
hostthread_handle_t hostthread_init(void *sched, int mcpus, env_atomic64 *cnt);

#endif /* HOST_THREAD_H */
