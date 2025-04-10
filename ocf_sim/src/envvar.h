/*
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _ENVVAR_H_
#define	_ENVVAR_H_

#include <stdint.h>

#ifdef _ENVVAR_C_
	#define	EXTERN_CONST
	#define	DEFAULT_VAL(_val)	= _val
#else
	#define	EXTERN_CONST	extern const
	#define	DEFAULT_VAL(_val)
#endif

#define ENVVAR_RESET_COUNTERS()		(c_reset_counters)
#define	ENVVAR_HTHREAD_MODE_POLL()	(c_hthread_mode == 'P')
#define	ENVVAR_HTHREAD_MODE_TRIGGER()	(c_hthread_mode == 'T')
#define	ENVVAR_AFFINITY()		(c_affinity)
#define	ENVVAR_AFFINITY_NORMAL()	(c_affinity == 1)
#define	ENVVAR_AFFINITY_SPECIAL()	(c_affinity == 2)
#define ENVVAR_SCHED_MODE(_mode)	(c_scheduler_mode == (_mode))

// Controls how the Host IOs are injected into the ocf

// 0: Legacy mode	The next hio is injected to the hio when the following condition is true
// 			a. The time is >= to the next hio ts.
//
// 1: Complete		The next hio is injected to the hio when both of the following conditions are true
// 			a. The time is >= to the next hio ts.
// 			b. All the 'C's that arrived in the original workload before this 'Q' already arrived
// 2: Max Active Qs	The next hio is injected to the hio when both of the following conditions are true
// 			a. The current number of Qs in the OCF is less than the number of the active Qs in the orig benchmark
// 			b. All the 'C's that arrived in the original workload before this 'Q' already arrived
//
EXTERN_CONST uint64_t c_scheduler_mode DEFAULT_VAL(2);

// Vitual Time Factor - This controls how the Virtual Time is advanced
// 0: 		The virtual time is advanced according to the time on this machine
// 		and jumps to the minimum between the next io to complete and the next hio to send.
// ts_factor 	The time is advanced according to the time on this machine * the ts_factor" },
EXTERN_CONST uint64_t c_ts_factor DEFAULT_VAL(25);

EXTERN_CONST uint64_t c_continue_delay DEFAULT_VAL(50);		// Scheduler delay (usec) before continue with traces to let more "C" to arrive
EXTERN_CONST uint64_t c_reset_counters DEFAULT_VAL(1);		// Reset statistics between trace files
EXTERN_CONST uint64_t c_hdd_fixed_delay DEFAULT_VAL(4);		// Fixed delay (in additional to the IO time and seek time) in usec
EXTERN_CONST uint64_t c_nvme_fixed_delay DEFAULT_VAL(4);	// Fixed delay (in additional to the IO time) in usec
EXTERN_CONST uint64_t c_ddr_fixed_delay DEFAULT_VAL(1);		// Fixed delay (in additional to the IO time) in usec
EXTERN_CONST uint64_t c_hdd_seek_time DEFAULT_VAL(4000);	// Core average seek time in usec
EXTERN_CONST uint64_t c_hdd_io_delay DEFAULT_VAL(0);		// Orig HDD IO delay in usec - used for backward compatible mode
EXTERN_CONST uint64_t c_nvme_io_delay DEFAULT_VAL(0);		// Orig NVMe IO delay in usec - used for backward compatible mode
EXTERN_CONST uint64_t c_hdd_bw_mbs DEFAULT_VAL(200);		// Core bandwidth - default is 200 MB/s
EXTERN_CONST uint64_t c_nvme_bw_mbs DEFAULT_VAL(7 * 1024);	// Cache bandwidth - default is 7 GB/s
EXTERN_CONST uint64_t c_ddr_bw_mbs DEFAULT_VAL(7 * 1024);	// DDR bandwidth - default is 7 GB/s
EXTERN_CONST char c_hthread_mode DEFAULT_VAL('T');		// Host thread mode - T(rigger) / P(olling)
EXTERN_CONST int c_affinity DEFAULT_VAL(2);			// Threads affinity - 0 (none) / 1 (notmal - enabled) / 2 (threads assign to cpus but traces no)
EXTERN_CONST int c_create_bin_files DEFAULT_VAL(0);		// When != 0 - only creates the binary trace files and exists

int envvar_init(void);
#endif
