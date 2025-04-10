/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __VOL_SIM_H__
#define __VOL_SIM_H__

#include <stdio.h>

#include "ocf/ocf_types.h"
#include "ocf/ocf_io.h"
#include "ocf/ocf_blktrace.h"

#include "device.h"
#include "host_io.h"

typedef struct {
	int32_t mi;
	int16_t mj;
	device_type_t device_type;
} volsim_init_params_t;

void volsim_clear(ocf_volume_t volume);
void volsim_create(ocf_volume_t volume);
void volsim_destroy(ocf_volume_t volume);
int16_t volsim_get_mj(ocf_volume_t volume);
int32_t volsim_get_mi(ocf_volume_t volume);
long volsim_get_last_c_q_idx(ocf_volume_t volume);
ocf_io_t *volsim_handle_complete(uint64_t ts, uint64_t *io_end_ts);
void volsim_orig_io_completed(ocf_io_t io);
void volsim_io_completed(ocf_io_t *ocf_io);
void volsim_io_submited(ocf_io_t *ocf_io);
bool volsim_is_physical_device(ocf_volume_t volume);
void volsim_set_init_params(ocf_volume_t volume, volsim_init_params_t *init_params);
void volsim_submit_io(ocf_io_t *ocf_io);
void volsim_trace_file_stats(HostIO *hio);
void volsim_update_q_c_stat(uint64_t q_c, uint64_t ts);
void volsim_print_tf_report(int trace_file_idx, uint64_t req_cnt);
void volsim_print_vol_report(int trace_file_idx, uint64_t req_cnt);

#endif
