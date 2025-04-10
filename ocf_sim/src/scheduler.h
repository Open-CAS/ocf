/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _SCHEDULER_H
#define _SCHEDULER_H

#include "cas_lib.h"

#include <ocf/ocf.h>

#include "host_io.h"

typedef struct _print_stats_params {
	int* stats_pipe;
	enum output_format_t out_format;
} print_stats_params;

typedef struct scheduler_s *scheduler_t;

typedef enum {
	E_SCHEDULER_EXEC_IO,	// Hostthread should execute the IO.
	E_SCHEDULER_YIELD,	// Hostthread should yield
	E_SCHEDULER_WAIT,	// Hostthread should wait to be trigerred
	E_SCHEDULER_DONE	// Hostthread should mark itself as done and then wait to be triggered
} scheduler_directive_t;

void scheduler_set_instance(scheduler_t instance);
scheduler_t scheduler_get_instance();
bool scheduler_is_active(void);
scheduler_t scheduler_create(int mcpus, print_stats_params* stats_info);
void scheduler_run_workload(scheduler_t self);
HostIO *scheduler_next_hio(scheduler_t self, int cpu, long *last_hio_idx, scheduler_directive_t *directive);
uint64_t scheduler_get_current_time(scheduler_t self, uint64_t *crt);
void scheduler_destroy(scheduler_t self);

#endif
