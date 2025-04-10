/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef HOST_IO_H
#define HOST_IO_H

#include "core.h"

#define OCF_DISCARD		2

typedef enum _pipe_idx_t {
	PIPE_IDX_READ = 0,
	PIPE_IDX_WRITE = 1,
	PIPE_IDX_MAX = 2
} pipe_idx_t;

#define	HOST_IO_VER	"05"	// Increment this each time there is a change in HostIO datatype

typedef struct _HostIO {
	uint64_t offset;
	uint64_t cpu;
	uint64_t size;
	uint64_t timestamp;
	uint64_t duration;	// Time between the Q and C (Used for the bin file)
	uint64_t active_q_cnt;	// Number of active Qs (Used for the bin file)
	long idx;
	long last_c_idx;
	core_handle_t core_handle;
	volatile int q_cpu;	// Used by the scheduler when OCF_AFFINITY=0
	int32_t mi;		// Used for the bin file
	int16_t mj;		// Used for the bin file
	uint8_t drc;
} HostIO;

#endif /* HOST_IO_H */
