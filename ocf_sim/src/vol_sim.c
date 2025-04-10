/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "vol_sim.h"

#include <ocf_env.h>

#include "ocf/ocf_def_priv.h"
#include "ocf/ocf_types.h"
#include "ocf/ocf_io.h"
#include "ocf/ocf_cache_priv.h"
#include "ocf/ocf_composite_volume.h"
#include "ocf/ocf_volume_priv.h"
#include "ocf/ocf_blktrace.h"

#include "blktrace.h"
#include "cache.h"
#include "core.h"
#include "cqueue.h"
#include "ctx.h"
#include "device.h"
#include "mocks.h"
#include "volume.h"
#include "statistics_view.h"

#define BLK4K(_bytes)			((uint64_t)((_bytes) / (4 * KiB)))
#define BYTES(_sectors)			((_sectors) << ENV_SECTOR_SHIFT)
#define NS_TO_SEC(_ns)   		((((_ns) / 500000000) + 1) >> 1)
#define NS_TO_USEC(_ns)   		((((_ns) / 500) + 1) >> 1)
#define SECURE_DIV(_a, _b)		((_b) ? (((_a) + (_b >> 1)) / _b) : 0)

#define FOR_ALL_COMP_VOLUMES(_h, _v)	\
		for (int i = 0;	(_v = ocf_composite_volume_get_subvolume_by_index(ocf_cache_get_volume(cache_get_cache(_h)), i)); i++)

#define UINT64_STRUCT_ADD(_a_struct, _b_struct)					\
	do {									\
		uint64_t *_a = (uint64_t *)&(_a_struct);			\
		uint64_t *_b = (uint64_t *)&(_b_struct);			\
		size_t _elements = sizeof(_a_struct) / sizeof(uint64_t);	\
		do {								\
			*_a++ += *_b++;						\
		} while (--_elements);						\
	} while (0)

typedef enum {
	E_TRACE_FILE_REPORT,
	E_FRONT_VOLUME_REPORT,
	E_BACK_VOLUME_REPORT,
	E_MAX_REPORTS
} report_t;

typedef struct {
	uint64_t idle;
	uint64_t duration;
	uint64_t c;
	uint64_t orig_io_c_ts;
	uint64_t orig_io_c_crt;
} stats_t;

typedef struct {
	device_io_data_t total;
	stats_t total_stats;
	uint8_t metadata_start[0];
	FILE *fp[2];
	uint64_t req_cnt;
	int file_idx;
	report_t report_type;
} print_handle_t;

typedef struct ocf_volsim_s {
	uint64_t start_ts;			// Timestamp of first action
	uint64_t end_ts;			// Timestamp of last action
	env_atomic64 idle_time;			// Time the device is not busy
	env_atomic64 last_c_ts;			// Timestamp of the last completed IO
	env_atomic64 c;				// The complete time of the IO (Q-->C)
	env_atomic64 orig_io_c_ts;		// The complete time of the orig IO (Q-->C) - virtual time
	env_atomic64 orig_io_c_crt;		// The complete time of the orig IO (Q-->C) - clock realtime
	env_atomic64 last_c_q_idx;		// Index of the request of the last C
	device_io_data_t io_data;
	env_atomic active_ios;			// The number of active IOs
	ocf_io_t *first_io_to_expire;	// First IO to expire
	uint8_t metadata_start[0];		// Up to here it is cleaned in volsim_clear.
	volsim_init_params_t init_params;
	CQueueHead *queue;
} data_t;

static data_t s_dummy_volsim = {	// Used for non-io requests (e.g. cleaner master req)
		.init_params.device_type = E_DEVICE_NONE,
		.init_params.mj = -2,
		.init_params.mi = -2
	};
static uint64_t s_max_active_q = 0;	// Max active Qs
static uint64_t s_start_crt = 0;       // Clock realtime of the beginning
static uint64_t s_ts = 0;		// Timestamp of the max active Qs

// IO Complete statistics
//#define	IO_COMP_STAT
#ifndef IO_COMP_STAT
#define	IO_COMP_STAT_UPD(_ts, _comp_ns)
#define IO_COMP_STAT_CLOSE()
#else
#define	IO_COMP_STAT_UPD(_ts, _comp_ns)		upd_comp(_ts, _comp_ns)
#define IO_COMP_STAT_CLOSE()			upd_comp(ULLONG_MAX, 0)

static void upd_comp(uint64_t ts, uint64_t comp)
{
	static FILE *s_fp = NULL;
	static uint64_t s_comp = 0, s_sec = 0;
	static char name[] = "comp0.csv";

	uint64_t sec = ts / 1000000000;
	if (s_fp == NULL) {
		s_sec = s_comp = 0;
		name[4]++;
		s_fp = fopen(name, "w");
	}
	if (sec > s_sec) {
		fprintf(s_fp, "%lu, %lu\n", s_sec, s_comp);
		s_comp = 0;
		s_sec = sec;
	}
	if (ts == ULLONG_MAX) {
		fclose(s_fp);
		s_fp = NULL;
	} else {
		s_comp += comp;
	}
}
#endif

static inline void atomic64_max(env_atomic64 *a, uint64_t val)
{
	uint64_t old = env_atomic64_read(a);
	uint64_t new;

	while(old < val && (new = env_atomic64_cmpxchg(a, old, val)) != old) {
		old = new;
	}
}

static inline data_t *data_ptr(ocf_volume_t volume)
{
	return (data_t *)(unlikely(volume == NULL || volume->ocf_volsim == NULL)
				? &s_dummy_volsim : volume->ocf_volsim);
}

static inline void clear_data(ocf_volume_t volume)
{
	memset(data_ptr(volume), 0, offsetof(data_t, metadata_start));
}

void volsim_clear(ocf_volume_t volume)
{
	if (volume) {
		clear_data(volume);
	} else {
		CACHE_LOOP_ALL(cache_handle) {
			ocf_volume_t volume;
			if (cache_is_composite(cache_handle)) {
				FOR_ALL_COMP_VOLUMES(cache_handle, volume) {
					clear_data(volume);
				}
			} else {
				volume = ocf_cache_get_volume(cache_get_cache(cache_handle));
				clear_data(volume);
			}
		}
		ocf_cache_t cache = ocf_cache_ml_get_main_cache(cache_get_cache(cache_get_next(NULL)));
		ocf_core_t core;
		ocf_core_id_t core_id;

		// Print Stats
		for_each_core(cache, core, core_id) {
			volume = ocf_core_get_front_volume(core);
			clear_data(volume);
			volume = ocf_core_get_volume(core);
			clear_data(volume);
		}
		s_max_active_q = s_ts = 0;
	}
	s_start_crt = clock_realtime();
}

void volsim_create(ocf_volume_t volume)
{
	ENV_BUG_ON(volume->ocf_volsim);
	volume->ocf_volsim = env_zalloc(sizeof(data_t), ENV_MEM_NORMAL);
	data_t *volsim = data_ptr(volume);

	volsim->init_params.mj = -1;
	volsim->init_params.mi = -1;

	volsim->queue = cqueue_create();
}

void volsim_destroy(ocf_volume_t volume)
{
	if (volume->ocf_volsim == NULL) {
		return;
	}

	data_t *volsim = data_ptr(volume);

	if (volsim->queue) {
		cqueue_destroy(volsim->queue);
	}

	env_free(volume->ocf_volsim);
	volume->ocf_volsim = NULL;
}

int16_t volsim_get_mj(ocf_volume_t volume)
{
	return data_ptr(volume)->init_params.mj;
}

int32_t volsim_get_mi(ocf_volume_t volume)
{
	return data_ptr(volume)->init_params.mi;
}

long volsim_get_last_c_q_idx(ocf_volume_t volume)
{
	return env_atomic64_read(&data_ptr(volume)->last_c_q_idx);
}

// Update database when the io is issued (D)
static inline void update_on_d(ocf_volume_t volume)
{
	data_t *volsim = data_ptr(volume);
	if (volsim->first_io_to_expire != NULL) {
		return;		// This I/O was already handled
	}

	ocf_io_t *ocf_io = cqueue_pop(volsim->queue);
	if (ocf_io == NULL) {
		return;		// Q is empty
	}

	volsim->first_io_to_expire = ocf_io;
	device_io_data_t *io_data = &volsim->io_data;
	uint64_t ts = BLKTRACE_TS(ocf_io->blktrace->last_ts);
	uint64_t idle_time = device_update_io_data(volsim->init_params.device_type, ts, ocf_io->bytes, ocf_io->dir, io_data);

	env_atomic64_add(idle_time, &volsim->idle_time);
}

// Return the earlist to expire
static inline data_t *check_expiry(ocf_volume_t volume, data_t *earliest)
{
	data_t *current = data_ptr(volume);

	return (current->first_io_to_expire != NULL &&
			(earliest == NULL || earliest->io_data.io_end_ts > current->io_data.io_end_ts))
		? current : earliest;
}

// Check if there is an IO that is ready to complete
// Output:
//	= 0	No IO in queues.
//	> 0	Timestamp of the first io to complete (even if not completed yet)
// Return value: I/O if there is one ready to complete
ocf_io_t *volsim_handle_complete(uint64_t ts, uint64_t *io_end_ts)
{
	data_t *first_expiry = NULL;

	CACHE_LOOP_ALL(cache_handle) {
		ocf_volume_t volume;
		if (cache_is_composite(cache_handle)) {
			FOR_ALL_COMP_VOLUMES(cache_handle, volume) {
				update_on_d(volume);
				first_expiry = check_expiry(volume, first_expiry);
			}
		} else {
			volume = ocf_cache_get_volume(cache_get_cache(cache_handle));
			update_on_d(volume);
			first_expiry = check_expiry(volume, first_expiry);
		}
	}
	ocf_cache_t cache = ocf_cache_ml_get_main_cache(cache_get_cache(cache_get_next(NULL)));
	ocf_core_t core;
	ocf_core_id_t core_id;

	for_each_core(cache, core, core_id) {
		ocf_volume_t volume = ocf_core_get_volume(core);
		update_on_d(volume);
		first_expiry = check_expiry(volume, first_expiry);
	}

	// Qs are empty
	if (first_expiry == NULL) {
		*io_end_ts = 0;
		return NULL;
	}

	// Check if IO is ready to complete
	if ((*io_end_ts = first_expiry->io_data.io_end_ts) > ts) {
		return NULL;	// Not ready to complete
	}

	ocf_io_t *ocf_io = first_expiry->first_io_to_expire;
	first_expiry->first_io_to_expire = NULL;
	return ocf_io;
}

void volsim_set_init_params(ocf_volume_t volume, volsim_init_params_t *init_params)
{
	data_ptr(volume)->init_params = *init_params;
}

void volsim_orig_io_completed(ocf_io_t io)
{
	ocf_blktrace_io_t *blktrace = ocf_blktrace_get(ocf_io_to_req(io));
	data_t *volsim = data_ptr(ocf_io_get_volume(io));

	env_atomic64_add((BLKTRACE_TS(blktrace->last_ts) - BLKTRACE_TS(blktrace->q_ts)) ,&volsim->orig_io_c_ts);
	env_atomic64_add((BLKTRACE_CRT(blktrace->last_ts) - BLKTRACE_CRT(blktrace->q_ts)) ,&volsim->orig_io_c_crt);

	IO_COMP_STAT_UPD(BLKTRACE_TS(blktrace->last_ts), (BLKTRACE_TS(blktrace->last_ts) - BLKTRACE_TS(blktrace->q_ts)));
}

void volsim_io_completed(ocf_io_t *ocf_io)
{
	ocf_blktrace_io_t *blktrace = ocf_io->blktrace;
	data_t *volsim = data_ptr(ocf_io->volume);

	env_atomic64_add((BLKTRACE_TS(blktrace->last_ts) - BLKTRACE_TS(blktrace->q_ts)) ,&volsim->c);
	atomic64_max(&volsim->last_c_ts, BLKTRACE_TS(blktrace->last_ts));
	volsim->end_ts = OCF_MAX(volsim->end_ts, BLKTRACE_TS(blktrace->last_ts));

	long q_idx = blktrace->priv ? ((HostIO *)blktrace->priv)->idx : -1;
	atomic64_max(&volsim->last_c_q_idx, q_idx);
	env_atomic_dec(&volsim->active_ios);
}

void volsim_io_submited(ocf_io_t *ocf_io)
{
	ocf_blktrace_io_t *blktrace = ocf_io->blktrace;
	data_t *volsim = data_ptr(ocf_io->volume);

	if (volsim == &s_dummy_volsim) {
		return;
	}
	if (volsim->start_ts == 0) {
		volsim->start_ts = BLKTRACE_TS(blktrace->q_ts);
	}
	if (env_atomic_inc_return(&volsim->active_ios) == 1 &&
		volsim->init_params.device_type < E_DEVICE_FIRST_PHYSICAL) {	// The idle_time of the physical devices is updated in update_on_d
		uint64_t last_c_ts = env_atomic64_read(&volsim->last_c_ts);
		last_c_ts = OCF_MAX(last_c_ts, volsim->start_ts);
		env_atomic64_add((BLKTRACE_TS(blktrace->q_ts) - last_c_ts), &volsim->idle_time);
	}
	env_atomic64_inc(&volsim->io_data.rw_cnt[ocf_io->dir].io);
	env_atomic64_add(ocf_io->bytes, &volsim->io_data.rw_cnt[ocf_io->dir].bytes);
}

bool volsim_is_physical_device(ocf_volume_t volume)
{
	return (bool)(data_ptr(volume)->init_params.device_type >= E_DEVICE_FIRST_PHYSICAL);
}

void volsim_submit_io(ocf_io_t *ocf_io)
{
	cqueue_push(data_ptr(ocf_io->volume)->queue, ocf_io);
}

// Update Core Stats for the original trace
void volsim_trace_file_stats(HostIO *hio)
{
	data_t *volsim = data_ptr(ocf_core_get_front_volume(core_get_core(hio->core_handle)));
	uint64_t bytes = BYTES(hio->size);

	// Calculate the estimated I/O time
	device_update_io_data(E_DEVICE_HDD_1, hio->timestamp, bytes, hio->drc, &volsim->io_data);
	env_atomic64_inc(&volsim->io_data.rw_cnt[hio->drc].io);
	env_atomic64_add(bytes, &volsim->io_data.rw_cnt[hio->drc].bytes);

	// Set start_ts and update end_ts
	uint64_t last_c_ts = env_atomic64_read(&volsim->last_c_ts);
	uint64_t c_ts = hio->timestamp + hio->duration;

	if (volsim->start_ts == 0) {
		volsim->start_ts = hio->timestamp;
	} else if (hio->active_q_cnt == 1 && hio->timestamp > last_c_ts) {
		env_atomic64_add((hio->timestamp - last_c_ts), &volsim->idle_time);
	}
	volsim->end_ts = OCF_MAX(volsim->end_ts, c_ts);

	// Update rest of the DB
	atomic64_max(&volsim->last_c_ts, c_ts);
	volsim_update_q_c_stat(hio->active_q_cnt, hio->timestamp);
	env_atomic64_add(hio->duration , &volsim->c);
	IO_COMP_STAT_UPD(ts, hio->duration);
}

void volsim_update_q_c_stat(uint64_t q_c, uint64_t ts)
{
	if (s_max_active_q < q_c) {
		s_max_active_q = q_c;
		s_ts = ts;
	}
}

// ==================================== Print Statistics Start ====================================
static inline void print_row_generic(FILE *fp, char *tag, char *hdr,
					stats_t *stats, device_io_data_t *io_data)
{
	uint64_t io_rd = env_atomic64_read(&io_data->rw_cnt[0].io);
	uint64_t io_wr = env_atomic64_read(&io_data->rw_cnt[1].io);
	uint64_t blk4k_rd = BLK4K(env_atomic64_read(&io_data->rw_cnt[0].bytes));
	uint64_t blk4k_wr = BLK4K(env_atomic64_read(&io_data->rw_cnt[1].bytes));

	fprintf(fp, "%s%s,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu",
		tag, hdr, io_rd + io_wr, io_rd, io_wr, blk4k_rd + blk4k_wr, blk4k_rd, blk4k_wr,
		NS_TO_SEC(stats->duration), NS_TO_SEC(stats->idle), NS_TO_SEC(stats->c));
}

static inline void print_row_back_volume(FILE *fp, char *tag, char *hdr,
					stats_t *stats, device_io_data_t *io_data)
{
	print_row_generic(fp, tag, hdr, stats, io_data);

	fprintf(fp, ",%lu,%lu,%lu\n",
		NS_TO_SEC(io_data->qio_time), NS_TO_SEC(io_data->seek_time), NS_TO_SEC(io_data->io_time));
}

static inline void print_row_front_volume(FILE *fp, char *tag, char *hdr,
					stats_t *stats, device_io_data_t *io_data)
{
	print_row_generic(fp, tag, hdr, stats, io_data);

	fprintf(fp, "\n");
}

static inline void print_row_trace_file(FILE *fp, char *tag, char *hdr,
					stats_t *stats, device_io_data_t *io_data)
{
	print_row_generic(fp, tag, hdr, stats, io_data);

	fprintf(fp, ",%lu,%lu,%lu,%lu\n",
		NS_TO_SEC(io_data->qio_time + io_data->seek_time + io_data->io_time),
		NS_TO_SEC(io_data->qio_time), NS_TO_SEC(io_data->seek_time), NS_TO_SEC(io_data->io_time));
}

// Function pointers for printing differnt rows according to report type
static const void (*s_print_row[E_MAX_REPORTS])(FILE *, char *, char *, stats_t *, device_io_data_t *) = {
		print_row_trace_file,
		print_row_front_volume,
		print_row_back_volume,
	};

// Print summary and destroy the print environment
static void print_end(print_handle_t *print_handle)
{
	s_print_row[print_handle->report_type](print_handle->fp[1], TAG(TABLE_SECTION), "Total:",
			     			&print_handle->total_stats, &print_handle->total);
	fclose(print_handle->fp[1]);
	stat_format_output(print_handle->fp[0], stdout, TEXT);
	fclose(print_handle->fp[0]);

	if (print_handle->total_stats.orig_io_c_ts) {
		ocf_log_time(0, "%d - Total Completion Time: %lu sec, VTS = %lu sec (%lu usec per req), CRT =  %lu sec (%lu usec per req)\n",
				print_handle->file_idx,
				NS_TO_SEC(clock_realtime() - s_start_crt),
				NS_TO_SEC(print_handle->total_stats.orig_io_c_ts),
				NS_TO_USEC(SECURE_DIV(print_handle->total_stats.orig_io_c_ts, print_handle->req_cnt)),
				NS_TO_SEC(print_handle->total_stats.orig_io_c_crt),
				NS_TO_USEC(SECURE_DIV(print_handle->total_stats.orig_io_c_crt, print_handle->req_cnt)));
	}
	if (print_handle->report_type == E_TRACE_FILE_REPORT || print_handle->total_stats.orig_io_c_ts) {
		ocf_log_time(0, "%lu.%lu: Max active Qs = %lu\n",
				s_ts / SEC(1), s_ts % SEC(1), s_max_active_q);
	}
	printf("\n");
	IO_COMP_STAT_CLOSE();
}

// Print a single row
static void print_row(ocf_volume_t volume, print_handle_t *print_handle)
{
	data_t *volsim = data_ptr(volume);
	stats_t stats = {
		.duration = volsim->end_ts - volsim->start_ts,
		.idle = env_atomic64_read(&volsim->idle_time),
		.c = env_atomic64_read(&volsim->c),
		.orig_io_c_ts = env_atomic64_read(&volsim->orig_io_c_ts),
		.orig_io_c_crt = env_atomic64_read(&volsim->orig_io_c_crt)
	};
	char device_buf[32];

	sprintf(device_buf, "\"%u,%u\"", volsim_get_mj(volume), volsim_get_mi(volume));
	s_print_row[print_handle->report_type](print_handle->fp[1], TAG(TABLE_ROW), device_buf,
						&stats , &volsim->io_data);

	UINT64_STRUCT_ADD(print_handle->total_stats, stats);
	UINT64_STRUCT_ADD(print_handle->total, volsim->io_data);
}

// Create the print environment and print header
static void print_start(print_handle_t *print_handle)
{
	static const char *generic_hdr[] = {
			TAG(TABLE_HEADER), "Device", ",I/Os", ",RD_IOs", ",WR_IOs",
			",4KBlocks", ",RD_4KBlocks", ",WR_4KBlocks",
			",Time(s)", ",Idle(s)", ",Act.C(s)"
		};
	static const char *trace_file[] = {
			"Est.C(s)","DevQ(s)", "Seek(s)", "IO(s)"
		};
	static const char *front_volume[] = {
		};
	static const char *back_volume[] = {
			"DevQ(s)", "Seek(s)", "IO(s)"
		};
	static const struct {
		const char *title;
		const char **hdr;
		uint hdr_cnt;
	} header[E_MAX_REPORTS] = {
		{ "Trace File", trace_file, ARRAY_SIZE(trace_file) },
		{ "Front Volumes", front_volume, ARRAY_SIZE(front_volume) },
		{ "Back Volumes", back_volume, ARRAY_SIZE(back_volume) },
	};

	if (create_pipe_pair(print_handle->fp)) {
		cas_printf(LOG_ERR, "Failed to create unidirectional pipe.\n");
		return;
	}

	ocf_log_time(0, "%s Statistics\n", header[print_handle->report_type].title);

	for (uint i = 0; i < ARRAY_SIZE(generic_hdr); i++) {
		fprintf(print_handle->fp[1], "%s", generic_hdr[i]);
	}
	for (uint i = 0; i < header[print_handle->report_type].hdr_cnt; i++) {
		fprintf(print_handle->fp[1], ",%s", header[print_handle->report_type].hdr[i]);
	}
	fputc('\n', print_handle->fp[1]);
	fflush(print_handle->fp[1]);
	memset(print_handle, 0, offsetof(print_handle_t, metadata_start));
}

static inline uint64_t get_io_cnt(ocf_volume_t volume)
{
	data_t *volsim = data_ptr(volume);
	uint64_t io_rd = env_atomic64_read(&volsim->io_data.rw_cnt[0].io);
	uint64_t io_wr = env_atomic64_read(&volsim->io_data.rw_cnt[1].io);

	return io_rd + io_wr;
}

static void print_back_volume_report(print_handle_t *print_handle)
{
	print_start(print_handle);

	// Print Cache Stats
	CACHE_LOOP_ALL(cache_handle) {
		ocf_volume_t volume;
		if (cache_is_composite(cache_handle)) {
			FOR_ALL_COMP_VOLUMES(cache_handle, volume) {
				print_row(volume, print_handle);
			}
		} else {
			volume = ocf_cache_get_volume(cache_get_cache(cache_handle));
			print_row(volume, print_handle);
		}
	}

	// Print Core Back Volume Stats - relevant only for the main cache
	ocf_cache_t cache = ocf_cache_ml_get_main_cache(cache_get_cache(cache_get_next(NULL)));
	ocf_core_t core;
	ocf_core_id_t core_id;

	for_each_core(cache, core, core_id) {
		ocf_volume_t volume = ocf_core_get_volume(core);
		print_row(volume, print_handle);
	}

	// Print Totals
	print_end(print_handle);
}

// Front volume is relevant only for the main cache
static void print_front_volume_report(print_handle_t *print_handle)
{
	ocf_cache_t cache = ocf_cache_ml_get_main_cache(cache_get_cache(cache_get_next(NULL)));
	ocf_core_t core;
	ocf_core_id_t core_id;

	// Print Header
	print_start(print_handle);

	// Print Stats
	for_each_core(cache, core, core_id) {
		ocf_volume_t volume = ocf_core_get_front_volume(core);
		print_row(volume, print_handle);
	}

	// Print Totals
	print_end(print_handle);
}

void volsim_print_tf_report(int trace_file_idx, uint64_t req_cnt)
{
	print_handle_t print_handle = {
		.report_type = E_TRACE_FILE_REPORT,
		.req_cnt = req_cnt,
		.file_idx = trace_file_idx
	};

	print_front_volume_report(&print_handle);
}

void volsim_print_vol_report(int trace_file_idx, uint64_t req_cnt)
{
	print_handle_t print_handle = {
		.report_type = E_FRONT_VOLUME_REPORT,
		.req_cnt = req_cnt,
		.file_idx = trace_file_idx
	};

	// Print the Front volume report
	print_front_volume_report(&print_handle);

	print_handle.report_type = E_BACK_VOLUME_REPORT;
	print_back_volume_report(&print_handle);
}
// ===================================== Print Statistics End =====================================
