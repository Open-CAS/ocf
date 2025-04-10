/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "blktrace.h"

#include <stdio.h>
#include <unistd.h>

#include <linux/blktrace_api.h>

#include "ocf/ocf_blktrace.h"

#include <pthread.h>
#include <sched.h>

#include "ocf/ocf_types.h"

#include "ctx.h"
#include "scheduler.h"
#include "vol_sim.h"


#define MAJOR_SHIFT	20

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define BE_32(_le)		__bswap_32(_le)
#define BE_64(_le)		__bswap_64(_le)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define BE_32(_be)		(_be)
#define BE_64(_be)		(_be)
#else
#error "Missing/Illegal __BYTE_ORDER compilation switch"
#endif

#define MAX_LENGTH_PTHREAD_NAME (16)
#define SEC_PART(_ts)		((_ts) / 1000000000)
#define NS_PART(_ts)		((_ts) % 1000000000)
typedef struct {
	FILE *fp;
	env_atomic64 sequence;
} cpu_info_t;

static cpu_info_t *s_cpu_info = NULL;
static uint s_cpu_cnt = 0;
static char s_path[100] = "";

/* Get the current timestamp and delta time */
static void handle_time(ocf_blktrace_action_t action, ocf_io_t *ocf_io, char *delta_str, ocf_blktrace_ts_t *ts)
{
	ocf_blktrace_io_t *blktrace = ocf_io->blktrace;
	uint64_t delta_time;
	struct ocf_request *req;
	ocf_forward_token_t token;

	BLKTRACE_TS(*ts) = scheduler_get_current_time(scheduler_get_instance(), &BLKTRACE_CRT(*ts));

	// Because the ts "jumps" when the scheduler is "idle" we use it only for delta time calculations
	// when exiting from queues or locks, otherwise we use the clock_realtime
	switch(action) {
		case ocf_blktrace_action_new_app:
			blktrace->q_ts = *ts;
			volsim_io_submited(ocf_io);
			delta_time = 0;
			break;

		case ocf_blktrace_action_new_ocf:
			blktrace->q_ts = *ts;
			if (volsim_is_physical_device(ocf_io->volume)) {
				volsim_io_submited(ocf_io);
			}
			delta_time = BLKTRACE_TS(blktrace->last_ts)
					? (BLKTRACE_TS(*ts) - BLKTRACE_TS(blktrace->last_ts))
					: 0;
			break;

		case ocf_blktrace_action_remap:
			token = (ocf_forward_token_t)ocf_io->priv;
			req = ocf_req_forward_token_to_req(token);
			if (ocf_cache_ml_get_lower_core(req->core) != NULL) {	// If there is a lower core volsim_io_submited is called by ocf_blktrace_action_new_ocf
				delta_time = BLKTRACE_CRT(*ts) - BLKTRACE_CRT(blktrace->last_ts);
				break;
			}
		case ocf_blktrace_action_remap_to_cache:
			blktrace->q_ts = *ts;
			volsim_io_submited(ocf_io);
		case ocf_blktrace_action_inserted:
		case ocf_blktrace_action_async_lock:
		case ocf_blktrace_action_async_wait:
		case ocf_blktrace_action_sync_lock:
		case ocf_blktrace_action_issued:
		case ocf_blktrace_action_debug:
			delta_time = BLKTRACE_CRT(*ts) - BLKTRACE_CRT(blktrace->last_ts);
			break;

		case ocf_blktrace_action_complete:
			delta_time = BLKTRACE_TS(*ts) - BLKTRACE_TS(blktrace->last_ts);
			blktrace->last_ts = *ts;
			volsim_io_completed(ocf_io);
			break;

		case ocf_blktrace_action_extracted:
		case ocf_blktrace_action_async_resume:
		case ocf_blktrace_action_sync_unlock:
			delta_time = BLKTRACE_TS(*ts) - BLKTRACE_TS(blktrace->last_ts);
			break;

		default:
			delta_time = 0;
			break;
	}

	if (delta_time) {
		sprintf(delta_str, "(%lu)", delta_time);
	} else {
		strcpy(delta_str, ".");		// Needed for importing to excel
	}
}

/* Get the action symbol */
static const char *get_action(ocf_blktrace_action_t action)
{
	static const char *action_str[ocf_blktrace_action_cnt] = {	/* Must be in the same order of ocf_blktrace_action_t */
		"Q", 	// ocf_blktrace_action_new_app,
		"q", 	// ocf_blktrace_action_new_ocf,
		"A", 	// ocf_blktrace_action_remap,
		"a", 	// ocf_blktrace_action_remap_to_cache,
		"I", 	// ocf_blktrace_action_inserted,
		"e", 	// ocf_blktrace_action_extracted,
		"l", 	// ocf_blktrace_action_async_lock,
		"w", 	// ocf_blktrace_action_async_wait,
		"r", 	// ocf_blktrace_action_async_resume,
		"v", 	// ocf_blktrace_action_sync_lock,
		"u", 	// ocf_blktrace_action_sync_unlock,
		"D", 	// ocf_blktrace_action_issued,
		"C", 	// ocf_blktrace_action_complete,
		"z", 	// ocf_blktrace_action_debug
	};
	return ((uint)action < ocf_blktrace_action_cnt) ? action_str[action] : "?";
}

static void get_cpu_info(char *cpu_str)
{
	char pthread_name[MAX_LENGTH_PTHREAD_NAME];
	pthread_getname_np(pthread_self(), pthread_name, MAX_LENGTH_PTHREAD_NAME);
	int i = strncmp(pthread_name, "ocf_sim:", sizeof("ocf_sim")) ? 0 : sizeof("ocf_sim");

	sprintf(cpu_str, "%c[%d]", pthread_name[i], sched_getcpu());
}

static void remap_info(ocf_blktrace_orig_on_remap_t *orig_on_remap, char *remap_str)
{
	if (orig_on_remap) {
		int16_t mj = volsim_get_mj(orig_on_remap->volume);
		int32_t mi = volsim_get_mi(orig_on_remap->volume);
		sprintf(remap_str, "<- (%d,%d) %lu", mj, mi, orig_on_remap->addr >> ENV_SECTOR_SHIFT);
	} else {
		strcpy(remap_str, ". . .");		// Needed for importing to excel
	}
}

static void write_blktrace(const ocf_blktrace_const_data_t *const_data,
			   ocf_io_t *ocf_io,
			   ocf_blktrace_orig_on_remap_t *orig_on_remap,
			   ocf_blktrace_ts_t *ts)
{
	static const __u32 blk_ta_action[ocf_blktrace_action_cnt] = {	/* Must be in the same order of ocf_blktrace_action_t */
		BLK_TA_QUEUE, 		// ocf_blktrace_action_new_app,
		0, 			// ocf_blktrace_action_new_ocf,
		BLK_TA_REMAP, 		// ocf_blktrace_action_remap,
		BLK_TA_INSERT, 		// ocf_blktrace_action_inserted,
		0, 			// ocf_blktrace_action_extracted,
		0, 			// ocf_blktrace_action_async_lock,
		0,	 		// ocf_blktrace_action_async_wait,
		0, 			// ocf_blktrace_action_async_resume,
		0, 			// ocf_blktrace_action_sync_lock,
		0, 			// ocf_blktrace_action_sync_unlock,
		BLK_TA_ISSUE, 		// ocf_blktrace_action_issued,
		BLK_TA_COMPLETE,	// ocf_blktrace_action_complete,
		0, 			// ocf_blktrace_action_debug
	};

	int cpu = sched_getcpu();
	ENV_BUG_ON(cpu >= s_cpu_cnt);
	cpu_info_t *cpu_info = &s_cpu_info[cpu];
	if (cpu_info->fp == NULL) {
		return;
	}
	__u32 action = blk_ta_action[const_data->action];
	if (action == 0) {
		return;
	}
	uint pdu_len = orig_on_remap ? sizeof(struct blk_io_trace_remap) : 0;
	struct {
		struct blk_io_trace io_trace;
		struct blk_io_trace_remap io_trace_remap;
	} write_buf = {
		.io_trace.magic = BLK_IO_TRACE_MAGIC | BLK_IO_TRACE_VERSION,
		.io_trace.sequence = env_atomic64_inc_return(&cpu_info->sequence),
		.io_trace.time = BLKTRACE_TS(*ts),
		.io_trace.sector = ocf_io->addr >> ENV_SECTOR_SHIFT,
		.io_trace.bytes = ocf_io->bytes,
		.io_trace.action = action,
		.io_trace.pid = getpid(),
		.io_trace.cpu = cpu,
		.io_trace.pdu_len = pdu_len
	};

	ocf_volume_t volume = ocf_io->volume;
	int16_t mj = volsim_get_mj(volume);
	int32_t mi = volsim_get_mi(volume);
	write_buf.io_trace.device = ((__u32)mj << MAJOR_SHIFT) | mi;

	if (orig_on_remap) {
		mj = volsim_get_mj(orig_on_remap->volume);
		mi = volsim_get_mi(orig_on_remap->volume);
		write_buf.io_trace_remap.device_from = BE_32(((uint32_t)mj << MAJOR_SHIFT) | mi);
		write_buf.io_trace_remap.device_to = BE_32(write_buf.io_trace.device);
		write_buf.io_trace_remap.sector_from = BE_64(orig_on_remap->addr >> ENV_SECTOR_SHIFT);
	}
	// Write the blktrace data
	fwrite(&write_buf, sizeof(write_buf.io_trace) + pdu_len, 1, cpu_info->fp);
}

static void blktrace_cb_func(const ocf_blktrace_const_data_t *const_data,
			     ocf_io_t *ocf_io,
			     ocf_blktrace_orig_on_remap_t *orig_on_remap,
			     ocf_blktrace_ts_t *ts) // [OT] - Current timestamp
{
	ocf_blktrace_io_t *blktrace = ocf_io->blktrace;

	if (!OCF_BLKTRACE_IS_VALID(blktrace)) {
		ocf_log(2, "%s#%d:%s() - Missing OCF_BLKTRACE Signature\n",
			strrchr(const_data->file, '/') + 1, const_data->line, const_data->func);
		return;
	}

	// Time and Delta-Time - Needed regardless to the verbose level
	char delta_str[30];
	handle_time(const_data->action, ocf_io, delta_str, ts);

	write_blktrace(const_data, ocf_io, orig_on_remap, ts);
	extern uint8_t verbose;
	if (verbose == 0) {
		return;
	}

	// Device Major and Minor
	ocf_volume_t volume = ocf_io->volume;
	int16_t mj = volsim_get_mj(volume);
	int32_t mi = volsim_get_mi(volume);
	// CPU
	char cpu_str[7];
	get_cpu_info(cpu_str);

	// Orig request index
	long idx = blktrace->priv ? ((HostIO *)blktrace->priv)->idx : -1;

	// Direction and Prefetch ID
	char dir_str[4];
	char dir = ocf_io->dir ? 'W' : 'R';
	if (PA_ID_VALID(ocf_io->pa_id)) {
		sprintf(dir_str, "%cP%d", dir, ocf_io->pa_id);
	} else {
		sprintf(dir_str, "%c  ", dir);
	}

	// Section and number od sections
	uint64_t sec = ocf_io->addr >> ENV_SECTOR_SHIFT;
	uint32_t nsec = ocf_io->bytes >> ENV_SECTOR_SHIFT;

	// Remap info
	char remap_str[50];
	remap_info(orig_on_remap, remap_str);

	// Print
	printf("%4d,%-4d %-6s %8ld %5lu.%09lu %p %s %2s %10lu + %-6u %12s %-25s %-25s %5d %s\t%s\n",
		mj, mi, cpu_str, idx, SEC_PART(BLKTRACE_TS(*ts)), NS_PART(BLKTRACE_TS(*ts)), blktrace,
		get_action(const_data->action), dir_str, sec, nsec, delta_str, remap_str,
		strrchr(const_data->file, '/') + 1, const_data->line, const_data->func, const_data->text ? const_data->text : "");
}

void blktrace_init(void)
{
	ocf_blktrace_register_t reg = {
		.blktrace_ext_func = blktrace_cb_func,
		.volsim_create = volsim_create,
		.volsim_destroy = volsim_destroy
	};
	s_cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);
	s_cpu_info = calloc(s_cpu_cnt, sizeof(cpu_info_t));
	for (uint i = 0; i < s_cpu_cnt; i++) {
		env_atomic64_set(&s_cpu_info[i].sequence, 0);
	}
	ocf_blktrace_register(&reg);
}

void blktrace_set_path(char *path)
{
	if (path) {
		strncpy(s_path, path, sizeof(s_path) - 1);
		s_path[sizeof(s_path) - 1] = '\0';
	}
}

void blktrace_new(char *name)
{
	if (s_cpu_info == NULL || !s_path[0]) {
		return;
	}
	char fn[strlen(s_path) + strlen(name) + 20];
	strcpy(fn, s_path);
	char *p = strrchr(name, '/');
	if (p == NULL) {
		strcat(fn, "/");
		p = name;
	}
	strcat(fn, p);
	strcat(fn, ".blktrace.");
	char *cpu = strchr(fn, '\0');

	for (uint i = 0; i < s_cpu_cnt; i++) {
		sprintf(cpu, "%u", i);
		if (s_cpu_info[i].fp) {
			fclose(s_cpu_info[i].fp);
		}
		s_cpu_info[i].fp = fopen(fn, "w");
		if (s_cpu_info[i].fp == NULL) {
			printf("fopen(\"%s\", \"w\") failed\n", fn);
		}
		env_atomic64_set(&s_cpu_info[i].sequence, 0);
	}
}

void blktrace_cleanup(void)
{
	ocf_blktrace_de_register();
	for (uint i = 0; i < s_cpu_cnt; i++) {
		if (s_cpu_info[i].fp) {
			fclose(s_cpu_info[i].fp);
		}
	}
	if (s_cpu_info) {
		free(s_cpu_info);
	}
}
