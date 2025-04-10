/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "scheduler.h"

#include <math.h>

#include <ocf_env.h>
#include <../../ocf/ocf_def_priv.h>
#include <ocf/ocf_blktrace.h>

#include "blktrace.h"
#include "cache.h"
#include "core.h"
#include "cqueue.h"
#include "ctx.h"
#include "device.h"
#include "envvar.h"
#include "host_io.h"
#include "host_thread.h"
#include "trace_file.h"
#include "vol_sim.h"
#include "volume.h"


#define NO_CPU			(-1)

struct scheduler_s {
	volatile long hio_idx;
	volatile int trace_file_idx;
	int mcpus;
	int max_initiators;
	volatile struct {
		uint64_t crt;
		uint64_t ts;
	} exec_time;
	volatile struct _control_flow_ts {       // Used to control the scheduler
		uint64_t pending;
		uint64_t ok2continue;
	} control_flow_ts;
	volatile uint64_t last_activity_crt;
 	env_atomic64 q_cnt;
 	env_atomic64 c_cnt;
	HostIO* host_io_array;
	uint64_t host_io_array_size;
	int* initiator_to_cpu_map;
	int core_vol_arr_size;
	hostthread_handle_t hostthread_handle;
	print_stats_params* stats_info;
	CQueueHead *complete_queue;
};
static bool s_active = false;

void casadm_print_stats(int pipe_write);

static scheduler_t minstance = NULL;
void scheduler_set_instance(scheduler_t instance)
{
	// assert(minstance == NULL);
	minstance = instance;
}

scheduler_t scheduler_get_instance()
{
	return minstance;
}

bool scheduler_is_active(void)
{
	return s_active;
}

scheduler_t scheduler_create(int mcpus, print_stats_params* stats_info)
{
	scheduler_t self = calloc(1, sizeof(*self));		// Use calloc because of the 0 initialize.
	self->host_io_array = tracefile_get_hio_array(&self->host_io_array_size);
	self->mcpus = mcpus;
	self->initiator_to_cpu_map = tracefile_get_cpu_map(&self->max_initiators);
	self->stats_info = stats_info;
	self->complete_queue = cqueue_create();
	self->hostthread_handle = hostthread_init((void *)self, mcpus, &self->c_cnt);	// Must be last
	return self;
}

static void print_progress(scheduler_t self)
{
	static int last_pos = -1;

	if (verbose) {
		return;
	}
	int q_pos = 100 * env_atomic64_read(&self->q_cnt) / self->host_io_array_size;
	int c_pos = 100 * env_atomic64_read(&self->c_cnt) / self->host_io_array_size;
	int pos = (q_pos + c_pos) / 2;
	if (last_pos == pos) {
		return;
	}
	last_pos = pos;
	putchar('[');
	for (int i = 0; i < 100; ++i) {
		char c;
		if (i < c_pos) c = '=';
		else if (i < q_pos) c = '+';
		else if (i == q_pos) c = '>';
		else c = ' ';
		putchar(c);
	}
	printf("] Q: %d %%,  C: %d %%\r",q_pos, c_pos);
	fflush(stdout);
}

static void update_current_time(scheduler_t self, uint64_t ts)
{
	uint64_t crt;
	uint64_t current_ts = scheduler_get_current_time(self, &crt);

	if (current_ts < ts && (c_ts_factor == 0 || (crt > self->last_activity_crt + SEC(1)))) {
		self->exec_time.ts = ts;
		self->exec_time.crt = crt;
	}
}

static inline uint64_t get_active_q_cnt(scheduler_t self, bool inc_q)
{
	uint64_t q = inc_q ? env_atomic64_inc_return(&self->q_cnt) : env_atomic64_read(&self->q_cnt);
	uint64_t c = env_atomic64_read(&self->c_cnt);
	return (q > c) ? q - c : 0;
}

static inline bool ok_to_continue(scheduler_t self, HostIO *hio)
{
	if (hio == NULL) {
		return true;
	}
	bool mode0 = (bool)(hio->timestamp <= scheduler_get_current_time(self, NULL));
	bool mode1 = (bool)(hio->last_c_idx <= volsim_get_last_c_q_idx(ocf_core_get_front_volume(core_get_core(hio->core_handle))));
	if (ENVVAR_SCHED_MODE(2)) {
		return (bool)(mode1 && get_active_q_cnt(self, false) < hio->active_q_cnt);
	}
	return ENVVAR_SCHED_MODE(0) ? mode0 : (mode0 && mode1);
}

static inline void kick_threads(scheduler_t self)
{
	static int i = 0;

	hostthread_trigger(self->hostthread_handle, i);

	if (++i >= self->mcpus) {
		i = 0;
	}
	cache_kick_next_q();
}

// Read all the requests that are already completed
// Return value is the ts of the next expected complete.
static uint64_t handle_complete(scheduler_t self, uint64_t ts)
{
	ocf_io_t *ocf_io = NULL;
	uint64_t io_end_ts;

	while ((ocf_io = volsim_handle_complete(ts, &io_end_ts))) {
		cqueue_push(self->complete_queue, ocf_io);	// Move to the complete queue
		kick_threads(self);
	}
	kick_threads(self);
	return io_end_ts;
}

static bool check_rcv_ios(scheduler_t self, HostIO *next_hio)
{
	volatile struct _control_flow_ts *control_flow_ts = &self->control_flow_ts;
	bool rcv = false;

	do {
		uint64_t crt;
		uint64_t current_ts = scheduler_get_current_time(self, &crt);
		uint64_t ts = next_hio ? current_ts : ULLONG_MAX;
		uint64_t new_ts = handle_complete(self, ts);
		if (new_ts) {
			rcv = true;
		}
		// Give chance to requests that are still processed by the OCF to reach the device Qs.
		if (control_flow_ts->pending != new_ts) {
			control_flow_ts->pending = new_ts;
			control_flow_ts->ok2continue = crt + USEC(c_continue_delay);
		} else if (crt >= control_flow_ts->ok2continue) {
			if (new_ts == 0) {
				break;
			}
			if (ENVVAR_SCHED_MODE(0) && next_hio) {
				new_ts = OCF_MIN(new_ts, next_hio->timestamp);
			}
			update_current_time(self, new_ts);
		}
	} while (!ok_to_continue(self, next_hio));

	print_progress(self);

	return rcv;
}

static void drain_ios(scheduler_t self, HostIO *next_hio)
{
	// wait for io execution for all cpus
	ocf_log_time(2, "Drain ios\n");
	uint64_t t = clock_realtime() + MSEC(100);
	do {
		if (check_rcv_ios(self, next_hio) || env_atomic64_read(&self->q_cnt) > env_atomic64_read(&self->c_cnt)) {
			t = clock_realtime() + MSEC(100);
		}
	} while(clock_realtime() < t);
	ocf_log_time(2, "Drain ios - ended\n");
	self->last_activity_crt = 0;
}

#define CSV_STATS_ROWS	(100*1000)
#define CSV_STATS_PCT	(5)

void scheduler_run_workload(scheduler_t self)
{
	if (!ENVVAR_AFFINITY_NORMAL()) {
		for (uint i = 0; i < self->host_io_array_size; i++) {
			self->host_io_array[i].q_cpu = NO_CPU;
		}
	}
	env_atomic64_set(&self->q_cnt, 0);
	env_atomic64_set(&self->c_cnt, 0);
	self->trace_file_idx = -1;
	self->hio_idx = 0;
	hostthread_start(self->hostthread_handle);
	s_active = true;

	// Loop on all the trace file
	int trace_files_cnt = tracefile_get_cnt();
	for (self->trace_file_idx = 0; self->trace_file_idx < trace_files_cnt; self->trace_file_idx++) {
		int trace_len = tracefile_get_len(self->trace_file_idx);
		int nIos = (self->trace_file_idx && ENVVAR_RESET_COUNTERS())
				? (trace_len - tracefile_get_len(self->trace_file_idx - 1)) : trace_len;
		float stats_interval = min(CSV_STATS_ROWS, ((float)nIos * CSV_STATS_PCT) / 100);
		float next_range = stats_interval;

		if (self->trace_file_idx == 0 || ENVVAR_RESET_COUNTERS()) {
			volsim_clear(NULL);
		}
		blktrace_new(tracefile_get_name(self->trace_file_idx));
		uint64_t last_ts = self->exec_time.ts = self->host_io_array[self->hio_idx].timestamp;
		self->exec_time.crt = clock_realtime();
		HostIO *hio = &self->host_io_array[++self->hio_idx];	// Don't check for receive IO before the first Q
		for (int i = 0; i < self->mcpus; i++) {
			hostthread_trigger(self->hostthread_handle, i);
		}
		// Loop on the traces of the trace file
		while (self->hio_idx < trace_len) {
			check_rcv_ios(self, hio);
			if (hio->timestamp > last_ts + SEC(1)) {
				drain_ios(self, hio);
			}
			last_ts = hio->timestamp;

			update_current_time(self, hio->timestamp);
			int local_cpu = self->initiator_to_cpu_map[hio->cpu];
			hostthread_trigger(self->hostthread_handle, local_cpu);
			if (self->stats_info->out_format == OUTPUT_FORMAT_CSV && env_atomic64_read(&self->c_cnt) >= roundf(next_range)) {
				casadm_print_stats(self->stats_info->stats_pipe[PIPE_IDX_WRITE]);
				next_range += stats_interval;
			}
			self->hio_idx++;
			hio++;
		}
		if (self->hio_idx >= self->host_io_array_size) {
			hio = NULL;
		}
		do {
			drain_ios(self, hio);
		} while (hostthread_active(self->hostthread_handle));

		if (self->stats_info->out_format == OUTPUT_FORMAT_CSV) {
			next_range = env_atomic64_read(&self->c_cnt) + stats_interval;
		}

		ocf_log(0, "%s", "\n");
		ocf_log(0, "%s", tracefile_get_name(self->trace_file_idx));
		casadm_print_stats(self->stats_info->stats_pipe[PIPE_IDX_WRITE]);
		volsim_print_vol_report(self->trace_file_idx, (uint64_t)nIos);

		if (ENVVAR_RESET_COUNTERS()) {
			ocf_log_time(0, "OCF_RESET_COUNTERS\n");
			CACHE_LOOP_ALL(cache_handle) {
				reset_counters(cache_get_idx(cache_handle),
					OCF_CORE_ID_INVALID,
#ifdef OCF_DEBUG_STATS
					OCF_COMPOSITE_VOLUME_MEMBER_ID_INVALID,
#endif
					false);
			}
		}
	}
	s_active = false;
	drain_ios(self, NULL);
}

static inline bool hio_belongs_to_current_thread(scheduler_t self, int cpu, HostIO *hio)
{
	if (ENVVAR_AFFINITY_NORMAL()) {
		return (bool)(self->initiator_to_cpu_map[hio->cpu] == cpu);
	}
	return __sync_bool_compare_and_swap(&hio->q_cpu, NO_CPU, cpu);
}

static void complete_io(scheduler_t self)
{
	ocf_io_t *ocf_io;
	while ((ocf_io = cqueue_pop(self->complete_queue))) {
		volume_complete_io(ocf_io);
	}
	self->last_activity_crt = clock_realtime();
}

HostIO *scheduler_next_hio(scheduler_t self, int cpu, long *last_hio_idx, scheduler_directive_t *directive)
{
	complete_io(self);		// Handle all the IOs that are scheduled to be complete

	long hio_idx = *last_hio_idx;
	while (++hio_idx < self->hio_idx) {
		HostIO *hio = &self->host_io_array[hio_idx];
		if (ENVVAR_SCHED_MODE(2) && get_active_q_cnt(self, false) >= hio->active_q_cnt) {
			break;
		}
		if (hio_belongs_to_current_thread(self, cpu, hio)) {
			uint64_t q_c = get_active_q_cnt(self, true);
			uint64_t ts = scheduler_get_current_time(self, (uint64_t *)&self->last_activity_crt);
			volsim_update_q_c_stat(q_c, ts);
			*last_hio_idx = hio_idx;
			*directive = E_SCHEDULER_EXEC_IO;
			return hio;
		}
	}

	*last_hio_idx = hio_idx - 1;
	if (self->trace_file_idx < 0) {
		*directive = E_SCHEDULER_WAIT;
	} else if (hio_idx >= tracefile_get_len(self->trace_file_idx)) {
		*directive = E_SCHEDULER_DONE;
	} else if (ENVVAR_HTHREAD_MODE_POLL()) {
		*directive = E_SCHEDULER_YIELD;
	} else {
		*directive = E_SCHEDULER_WAIT;
	}
	return NULL;
}

uint64_t scheduler_get_current_time(scheduler_t self, uint64_t *crt)
{
	if (self == NULL && (self = scheduler_get_instance()) == NULL) {
		if (crt) *crt = 0;
		return 0;
	}
	uint64_t current_crt = clock_realtime();
	if (crt) {
		*crt = current_crt;
	}
	uint64_t delta_crt = current_crt - self->exec_time.crt;
	if (c_ts_factor) {
		delta_crt *= c_ts_factor;
	}
	uint64_t ts = self->exec_time.ts + delta_crt;
	return ts;
}

void scheduler_destroy(scheduler_t self)
{
	hostthread_cleanup(&self->hostthread_handle);
	cqueue_destroy(self->complete_queue);
	free(self);
}
