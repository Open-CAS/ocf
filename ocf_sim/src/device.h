/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __DEVICE_H__
#define __DEVICE_H__

#include <stdint.h>

#include <ocf_env.h>
#include "ocf/ocf_types.h"

typedef enum {
	E_DEVICE_NONE,
	E_DEVICE_CACHE,		// Used for the cache composite volume (father cache)
	E_DEVICE_FRONT,
	E_DEVICE_BACK,		// Used for the core back volume of the upper caches
	E_DEVICE_FIRST_PHYSICAL,
	E_DEVICE_HDD_1 = E_DEVICE_FIRST_PHYSICAL,
	E_DEVICE_NVME_1,
	E_DEVICE_DDR_1,
	E_DEVICE_MAX_TYPES
} device_type_t;

typedef struct {	// If one of these elements isn't uint64_t - need to update UINT64_STRUCT_ADD in volsim.c
	uint64_t qio_time;		// Time in the device queue while I/O is busy.
	uint64_t seek_time;		// Seek time.
	uint64_t io_time;		// I/O time.
	uint64_t io_end_ts;		// Timestamp when the io will end
	struct {
		env_atomic64 io;		// Number of I/Os
		env_atomic64 bytes;		// Number of I/O bytes
	} rw_cnt[2];
} device_io_data_t;

void device_init(void);
uint64_t device_update_io_data(device_type_t device_type, uint64_t ts, uint64_t bytes, uint8_t dir, device_io_data_t *io_data);

#endif
