/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "device.h"

#include <stdint.h>

#include <ocf_env.h>
#include "ocf/ocf_def_priv.h"

#include "envvar.h"

#define USEC_TO_NS(_us)			((_us) * 1000)

static uint64_t s_hdd_fixed_delay = 0;		// Fixed delay (in additional to the IO time and seek time) in usec
static uint64_t s_nvme_fixed_delay = 0;		// Fixed delay (in additional to the IO time) in usec
static uint64_t s_ddr_fixed_delay = 0;		// Fixed delay (in additional to the IO time) in usec
static uint64_t s_hdd_seek_time = 0;		// Core average seek time in usec
static uint64_t s_hdd_io_delay = 0;		// Orig HDD IO delay in usec - used for backward compatible mode
static uint64_t s_nvme_io_delay = 0;		// Orig NVMe IO delay in usec - used for backward compatible mode
static uint64_t s_ddr_io_delay = 0;		// Orig DDR IO delay in usec - used for backward compatible mode

void device_init(void)
{
	// Old mode (kept for backward compatible) - Get the Core and Cache IO delay
	if (c_hdd_io_delay || c_nvme_io_delay) {
		s_hdd_io_delay = USEC_TO_NS(c_hdd_io_delay);
		s_nvme_io_delay = USEC_TO_NS(c_nvme_io_delay);
		s_ddr_io_delay = USEC_TO_NS(c_nvme_io_delay);
	} else {
	// New mode - Get the Core and Cache fixed IO delay
		s_hdd_seek_time = USEC_TO_NS(c_hdd_seek_time);
		s_hdd_fixed_delay = USEC_TO_NS(c_hdd_fixed_delay);
		s_nvme_fixed_delay = USEC_TO_NS(c_nvme_fixed_delay);
		s_ddr_fixed_delay = USEC_TO_NS(c_ddr_fixed_delay);
	}
}

static inline uint64_t calculate_io_time(uint64_t bw, uint64_t bytes)
{
	// bw_mb_s = bw * 1024 * 1024
	// bw_b_ns = bw_mb_s / 1,000,000,000 = (bw * 1024 * 1024) / 1,000,000,000
	// io_time = bytes / bw_b_ns = bytes / ((bw * 1024 * 1024) / 1,000,000,000) ~= (bytes << 10) / bw
	return (bytes << 10) / bw;
}

static uint64_t update_io_data_ddr(uint64_t ts, uint64_t bytes, uint8_t dir, device_io_data_t *io_data)
{
	uint64_t idle_time;
	uint64_t io_time;

	if (io_data->io_end_ts < ts) {
		idle_time = (ts - io_data->io_end_ts);
	} else {
		idle_time = 0;
	}

	if (s_ddr_io_delay) {	// Backwards compatible
		io_time = s_ddr_io_delay;
		io_data->io_end_ts = ts + io_time;
	} else {
		io_time = s_ddr_fixed_delay + calculate_io_time(c_ddr_bw_mbs, bytes);
		io_data->io_end_ts = OCF_MAX(ts + io_time, io_data->io_end_ts);
	}
	io_data->io_time += io_time;

	return idle_time;
}

static uint64_t update_io_data_nvme(uint64_t ts, uint64_t bytes, uint8_t dir, device_io_data_t *io_data)
{
	uint64_t idle_time;
	uint64_t io_time;
	uint64_t qio_time;

	// Calculate the time in the I/O Q
	if (io_data->io_end_ts > ts) {	// I/O Q is not empty
		qio_time = io_data->io_end_ts - ts;	// Time in Q
		io_data->qio_time += qio_time;
		idle_time = 0;
	} else {
		qio_time = 0;
		idle_time = (ts - io_data->io_end_ts);
		io_data->io_end_ts = ts;
	}
	if (s_nvme_io_delay) {	// Backwards compatible
		io_time = s_nvme_io_delay - qio_time;
	} else {
		io_time = s_nvme_fixed_delay + calculate_io_time(c_nvme_bw_mbs, bytes);
	}
	io_data->io_time += io_time;
	io_data->io_end_ts += io_time;	// Time when Q will be empty

	return idle_time;
}

static uint64_t update_io_data_hdd(uint64_t ts, uint64_t bytes, uint8_t dir, device_io_data_t *io_data)
{
	// Calculate the I/O time
	uint64_t idle_time;
	uint64_t io_time;
	uint64_t qio_time;
	uint64_t seek_time;

	// Calculate the time in the I/O Q
	if (io_data->io_end_ts > ts) {	// I/O Q is not empty
		qio_time = io_data->io_end_ts - ts;	// Time in Q
		io_data->qio_time += qio_time;
		idle_time = 0;
		uint64_t t = (qio_time << 4) / c_hdd_bw_mbs;	// Seek time becomes smaller as Q is full
		seek_time = (s_hdd_seek_time > t) ? (s_hdd_seek_time - t) : 0;
	} else {
		qio_time = 0;
		idle_time = (ts - io_data->io_end_ts);
		io_data->io_end_ts = ts;
		seek_time = s_hdd_seek_time;		// Average seek time
	}
	if (s_hdd_io_delay) {	// Backwards compatible
		io_time = s_hdd_io_delay - qio_time;
		seek_time = 0;
	} else {
		io_time = s_hdd_fixed_delay + calculate_io_time(c_hdd_bw_mbs, bytes);
	}
	io_data->io_time += io_time;
	io_data->seek_time += seek_time;
	io_data->io_end_ts += (seek_time + io_time);	// Time when Q will be empty

	return idle_time;
}

uint64_t device_update_io_data(device_type_t device_type, uint64_t ts, uint64_t bytes, uint8_t dir, device_io_data_t *io_data)
{
	uint64_t idle_time = 0;

	switch (device_type) {
		case E_DEVICE_HDD_1:
			idle_time = update_io_data_hdd(ts, bytes, dir, io_data);
			break;

		case E_DEVICE_NVME_1:
			idle_time = update_io_data_nvme(ts, bytes, dir, io_data);
			break;

		case E_DEVICE_DDR_1:
			idle_time = update_io_data_ddr(ts, bytes, dir, io_data);
			break;

		default:
			ENV_BUG();
	}

	return idle_time;
}
