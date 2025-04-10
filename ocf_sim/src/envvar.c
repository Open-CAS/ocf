/*
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#define	_ENVVAR_C_
#include "envvar.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ocf_env.h>

typedef	enum {				// List of formats
	E_UINT64,
	E_CHAR,
	E_INT
} envvar_fmt_t;

typedef struct {
	const char *name;		// Environemnt variable name
	size_t argc;			// Items in argv
	const void **argv;		// List of pointers for the environemnt variables
	const envvar_fmt_t *format;	// List of formats
	int (*init_func)(const char *);	// Pointer to an init function (if NULL, we just print the value)
	const char *help;		// Help message
} envvar_t;

#define	X(_var_tbl)	ARRAY_SIZE(_var_tbl), (void *)(_var_tbl)
#define	N()		0, NULL

static int list(const char *name);

static const uint64_t *s_reset_counters[] = { &c_reset_counters };
static const uint64_t *s_continue_delay[] = { &c_continue_delay };
static const uint64_t *s_io_delay[] = { &c_hdd_io_delay, &c_nvme_io_delay };
static const uint64_t *s_bw_mbs[] = { &c_hdd_bw_mbs, &c_nvme_bw_mbs, &c_ddr_bw_mbs };
static const uint64_t *s_hdd_fixed_delay[] = { &c_hdd_fixed_delay };
static const uint64_t *s_nvme_fixed_delay[] = { &c_nvme_fixed_delay };
static const uint64_t *s_ddr_fixed_delay[] = { &c_ddr_fixed_delay };
static const uint64_t *s_hdd_seek_time[] = { &c_hdd_seek_time };
static const uint64_t *s_scheduler_mode[] = { &c_scheduler_mode };
static const uint64_t *s_ts_factor[] = { &c_ts_factor };
static const char *s_hthread_mode[] = { &c_hthread_mode };
static const int *s_affinity[] = { &c_affinity };
static const int *s_create_bin_files[] = { &c_create_bin_files };
static const envvar_fmt_t fmt_lu_lu_lu[] = { E_UINT64, E_UINT64, E_UINT64 };
static const envvar_fmt_t fmt_c[] = { E_CHAR };
static const envvar_fmt_t fmt_d[] = { E_INT };
static const envvar_t envvars[] = {
		{ "OCF_ENVVAR_LIST", N(), NULL, list,
			"List all the ocf_sim environment variables with their default values" },
		{ "OCF_CONTINUE_DELAY", X(s_continue_delay), fmt_lu_lu_lu, NULL,
			"Scheduler delay (usec) before continue with traces to let more 'C' to arrive" },
		{ "OCF_RESET_COUNTERS", X(s_reset_counters), fmt_lu_lu_lu, NULL,
			"Reset statistics between trace files" },
		{ "OCF_IO_DELAY", X(s_io_delay), fmt_lu_lu_lu, NULL,
			"Original core,cache,ddr IO delay in usec - used for backward compatible mode" },
		{ "OCF_BANDWIDTH", X(s_bw_mbs), fmt_lu_lu_lu, NULL,
			"HDD, NVMe, DDR bandwidth (MB/s)" },
		{ "OCF_HDD_IO_DELAY", X(s_hdd_fixed_delay), fmt_lu_lu_lu, NULL,
			"HDD fixed delay (in additional to the IO time and seek time) in usec" },
		{ "OCF_NVME_IO_DELAY", X(s_nvme_fixed_delay), fmt_lu_lu_lu, NULL,
			"NVMe fixed delay (in additional to the IO time) in usec" },
		{ "OCF_DDR_IO_DELAY", X(s_ddr_fixed_delay), fmt_lu_lu_lu, NULL,
			"DDR fixed delay (in additional to the IO time) in usec" },
		{ "OCF_CORE_SEEK_TIME", X(s_hdd_seek_time), fmt_lu_lu_lu, NULL,
			"Core average seek time in usec" },
		{ "OCF_HTHREAD_MODE", X(s_hthread_mode), fmt_c, NULL,
			"Host thread mode - T(rigger) / P(olling)" },
		{ "OCF_AFFINITY", X(s_affinity), fmt_d, NULL,
			"Threads affinity - 0 (none) / 1 (enabled - enabled) / 2 (threads assign to cpus but traces no)" },
		{ "OCF_CREATE_BIN_FILES", X(s_create_bin_files), fmt_d, NULL,
			"When != 0 - only creates the binary trace files and exists" },
		{ "OCF_SCHEDULER_MODE", X(s_scheduler_mode), fmt_lu_lu_lu, NULL,
			"Controls how the Host IOs are injected into the ocf\n\t\t\t\t"
			"0: Legacy mode		The next hio is injected to the hio when the following condition is true\n\t\t\t\t"
			"			a. The time is >= to the next hio ts.\n\t\t\t\t"
			"1: Complete		The next hio is injected to the hio when both of the following conditions are true\n\t\t\t\t"
			"			a. The time is >= to the next hio ts.\n\t\t\t\t"
			"			b. All the 'C's that arrived in the original workload before this 'Q' already arrived\n\t\t\t\t"
			"2: Max Active Qs	The next hio is injected to the hio when both of the following conditions are true\n\t\t\t\t"
		 	"			a. The current number of Qs in the OCF is less than the number of the active Qs in the orig benchmark\n\t\t\t\t"
		 	"			b. All the 'C's that arrived in the original workload before this 'Q' already arrived" },
		{ "OCF_TS_FACTOR", X(s_ts_factor), fmt_lu_lu_lu, NULL,
			"Vitual Time Factor - This controls how the Virtual Time is advanced\n\t\t\t\t"
			"0: 		The virtual time is advanced according to the time on this machine\n\t\t\t\t"
			"		and jumps to the minimum between the next io to complete and the next hio to send.\n\t\t\t\t"
			"ts_factor 	The time is advanced according to the time on this machine * the ts_factor" },
	};

static const char *envvar_get(const envvar_t *env, int *cnt)
{
	const char *envvar = getenv(env->name);
	const char *p = envvar;
	int i;

	*cnt = -1;
	for (i = 0; i < env->argc && p; i++) {
		int rc;
		if (env->argv[i] == NULL) {
			printf("%s(%d): Failed reading param %u of %s\n", __func__, __LINE__, i, p);
			return envvar;
		}
		switch (env->format[i]) {
			case E_UINT64:
				rc = sscanf(p, "%lu", (uint64_t *)env->argv[i]);
				break;

			case E_CHAR:
				rc = sscanf(p, "%c", (char *)env->argv[i]);
				break;

			case E_INT:
				rc = sscanf(p, "%d", (int *)env->argv[i]);
				break;

			default:
				printf("%s(%d): Unknown format for param %u of %s\n", __func__, __LINE__, i, p);
				return envvar;
		}
		if (rc != 1) {
			printf("%s(%d): Failed reading param %u of %s\n", __func__, __LINE__, i, p);
			return envvar;
		}
		if ((p = strchr(p, ','))) {
			p++;
		}
	}

	*cnt = i;
	return envvar;
}

static void envvar_print(const envvar_t *env, bool help)
{
	printf("%s", env->name);
	for (uint i = 0; i < env->argc; i++) {
		putchar(i ? ',' : '=');
		switch (env->format[i]) {
			case E_UINT64:
				printf("%lu", *(uint64_t *)env->argv[i]);
				break;

			case E_CHAR:
				printf("%c", *(char *)env->argv[i]);
				break;

			case E_INT:
				printf("%d", *(int *)env->argv[i]);
				break;

			default:
				printf("%s(%d): Unknown format for param %u of %s\n", __func__, __LINE__, i, env->name);
				break;
		}
	}
	if (help) {
		printf("\r\t\t\t\t%s", env->help);
	}
	putchar('\n');
}

static int list(const char *name)
{
	for (uint i = 0; i < ARRAY_SIZE(envvars); i++) {
		envvar_print(&envvars[i], true);
	}
	return -1;
}

int envvar_init(void)
{
	for (uint i = 0; i < ARRAY_SIZE(envvars); i++) {
		int cnt;
		const char *p = envvar_get(&envvars[i], &cnt);
		if (cnt < 0) {
			return -1;	// Parse error.
		} else if (p == NULL) {
			// Do nothing - environment variables are not mandatory
		} else if (envvars[i].init_func == NULL) {
			envvar_print(&envvars[i], false);
		} else if (envvars[i].init_func(envvars[i].name)) {
			return -1;	// Illegal value
		}
	}
	return 0;
}
