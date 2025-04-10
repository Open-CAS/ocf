/*
 * Copyright(c) 2019-2023 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>
#include "mocks.h"
#include "blktrace.h"
#include "cache.h"
#include "core.h"
#include "data.h"
#include "device.h"
#include "ctx.h"
#include "envvar.h"
#include "queue_thread.h"
#include "version.h"
#include "cas_lib.h"
#include <../../ocf/ocf_def_priv.h>
#include <unistd.h>
#include <ocf_env.h>
#include <fcntl.h>
#include "host_io.h"
#include "host_thread.h"
#include "volume.h"
#include "trace_file.h"
#include <sys/sysinfo.h>
#include "scheduler.h"

/*
 * macro to enable non-user features.
 * comment when delivering to external users.
 */
#define TEAM_FEATURES

uint64_t backend_vol_sz = 3840ULL * 1024 * 1024 * 1024;
uint64_t cache_vol_sz = 360ULL * 1024 * 1024 * 1024;
uint64_t top_msla_vol_sz = 0;
uint8_t verbose = 0;
int stats_pipe[PIPE_IDX_MAX];
uint64_t t;
int** per_init_num_ios;
ocf_ctx_t ctx;
#define MAX_LINE_LEN (10000)
char line_buffer[MAX_LINE_LEN];
enum output_format_t out_format = OUTPUT_FORMAT_TABLE;
bool print_to_file = false;
bool sigpipe_occurred = false;
#define OCCUPANCY_THRESHOLD_PERCENT (75)
#define READ_HIT_THRESHOLD_PERCENT (75)
#define NEXT_ITER_DIFF (25)
#define OUTFILE_MAX_LEN (200)
#define MAX_SUPPORTED_CACHE_VOLUMES (4)
#define DEFAULT_CACHE_VOL_SZ_IN_GIB (360ULL)

char outfile_name[OUTFILE_MAX_LEN] = { '\0' };
typedef struct _print_to_file_thread_data {
	FILE* outfile;
	int pipe_read;
} print_to_file_thread_data;

/*
 * Wrapper function for io submition.
 */
FILE* create_outfile()
{
	FILE* outfile;
	if (strlen(outfile_name) > 0) {
		outfile = fopen(outfile_name, "w+");
	}
	else {
		error("Option O chosen, no outfile given\n");
	}

	if (!outfile) {
		printf("failed to create outfile %s\n", outfile_name);
		exit(1);
	}

	return outfile;
}

bool is_header(char* line_buffer)
{
	if (strstr(line_buffer, "[4KiB Blocks]")) {
		return true;
	}
	return false;
}

static void* print_to_file_thread_run(void* arg)
{
	int line_idx = 0;
	char reading_buf[1];
	static bool first_csv_line = true;
	print_to_file_thread_data* self = (print_to_file_thread_data*)arg;

	while (read(self->pipe_read, reading_buf, 1) > 0) {
		line_buffer[line_idx++] = reading_buf[0];
		if (reading_buf[0] == '\0') {
			close(self->pipe_read);
		}
		else if (reading_buf[0] == '\n') {
			assert(line_idx < MAX_LINE_LEN);
			line_buffer[line_idx] = '\0';
			// write(1, line_buffer, line_idx);
			if (out_format == OUTPUT_FORMAT_TABLE) {
				fwrite(line_buffer, 1, line_idx, self->outfile);
			}
			else {
				if (first_csv_line || !is_header(line_buffer)) {
					fwrite(line_buffer, 1, line_idx, self->outfile);
					first_csv_line = false;
				}
			}
			line_idx = 0;
			fflush(self->outfile);
		}
	}


	pthread_exit(0);
	return NULL;
}

void casadm_print_stats(int pipe_write)
{
	static int save_out = 0;

	if (print_to_file) {
		if (-1 == pipe_write) {
			perror("opening pipe failed");
			exit(1);
		}
		if (save_out == 0) {
			save_out = dup(fileno(stdout));
		}
		if (-1 == dup2(pipe_write, fileno(stdout))) {
			perror("cannot redirect stdout");
			exit(1);
		}
	}
	else {
		printf("\n");
	}
	unsigned int filter_flags = STATS_FILTER_USAGE | STATS_FILTER_BLK | STATS_FILTER_PREFETCH | STATS_FILTER_REQ;

	switch (verbose) {
	case 2:
		filter_flags |= STATS_FILTER_ERR;
	case 1:
		filter_flags |= STATS_FILTER_CONF;
	default:
		break;
	}
	CACHE_LOOP_ALL(cache_handle) {
		ocf_cache_t cache = cache_get_cache(cache_handle);
		printf("\n");
		ocf_log_time(0, "printing stats for %s\n", ocf_cache_get_name(cache));
		cache_status(cache_get_idx(cache_handle), OCF_CORE_ID_INVALID, 0,
#ifdef OCF_DEBUG_STATS
				OCF_COMPOSITE_VOLUME_MEMBER_ID_INVALID,
#endif
				filter_flags, out_format, true, false);
	}

	if (print_to_file) {
		fflush(stdout);
		if (-1 == dup2(save_out, fileno(stdout))) {
			perror("cannot redirect stdout");
			exit(1);
		}
	}
}

pthread_t print_to_file_init(FILE** outfile, print_to_file_thread_data* data)
{
	int ret;
	pthread_t print_to_file_thread;

	*outfile = create_outfile();
	if (!*outfile) {
		error1("Faild to create outfile %s\n", outfile_name);
	}
	if (pipe(stats_pipe) == -1) {
		error("Error creating pipe\n");
	}
	data->outfile = *outfile;
	data->pipe_read = stats_pipe[PIPE_IDX_READ];
	ret = pthread_create(&print_to_file_thread, NULL, print_to_file_thread_run, data);
	if (ret) {
		error("Error creating pipe thread\n");
	}
	ret = pthread_setname_np(print_to_file_thread, "ocf_sim:format");
	if (ret) {
		printf("failed to set pipe thread name err:%d\n", ret);
		exit(ret);
	}
	return print_to_file_thread;
}

void print_to_file_end(pthread_t print_to_file_thread, FILE* outfile)
{
	char* str = "\0";
	int ignored __attribute__((unused)) = write(stats_pipe[PIPE_IDX_WRITE], str, 1);
	close(stats_pipe[PIPE_IDX_WRITE]);
	pthread_join(print_to_file_thread, NULL);
	fclose(outfile);
}

void perform_workload(int num_iterations, int mcpus)
{
	print_stats_params stats_info;
	ocf_log_time(0, "perform_workload\n");

	if (ENVVAR_AFFINITY_NORMAL()) {
		int num_init;
		tracefile_get_cpu_map(&num_init);
		mcpus = OCF_MIN(num_init, mcpus);
	}

	stats_info.out_format = out_format;
	stats_info.stats_pipe = stats_pipe;

	scheduler_t sim_scheduler = scheduler_create(mcpus, &stats_info);
	scheduler_set_instance(sim_scheduler);
	for (int i = 0; i < num_iterations; i++) {
		if (num_iterations > 1) {
			ocf_log(0, "========================================== ITERATION %d ============================================\n", i);
		}
		scheduler_run_workload(sim_scheduler);
	}
	// print end run stats for table format
	if (sigpipe_occurred) {
		sigpipe_occurred = false;
		casadm_print_stats(stats_pipe[PIPE_IDX_WRITE]);
	}

	scheduler_destroy(sim_scheduler);
	ocf_log_time(0, "perform_workload - finished\n");
}

void handler(int s)
{
	sigpipe_occurred = true;
}

int get_25_percent_upper(uint64_t fraction)
{
	if (fraction > 75) {
		return 100;
	}
	else if (fraction > 50) {
		return 75;
	}
	else if (fraction > 25) {
		return 50;
	}
	else {
		return 25;
	}
}

bool analyze_recommandation(uint64_t rd_hits_percent, uint64_t* current_cache_size_in_percent)
{
	if (rd_hits_percent > READ_HIT_THRESHOLD_PERCENT) {
		*current_cache_size_in_percent -= NEXT_ITER_DIFF;
		return true;
	}
	return false;
}

static bool check_need_to_retry(ocf_cache_t cache, bool recommend_cache_size, uint64_t* current_cache_size_in_percent, int* occupacy_cache_size_reported)
{
	bool retry = false;
	struct ocf_stats_usage usage;
	struct ocf_stats_requests req;
	if (ocf_stats_collect_cache(cache, &usage, &req, NULL, NULL))
		error("failed to read cache stats\n");
	usage.occupancy.fraction /= 100;

	if (usage.occupancy.fraction <= OCCUPANCY_THRESHOLD_PERCENT) {
		*occupacy_cache_size_reported = get_25_percent_upper(usage.occupancy.fraction);
		*current_cache_size_in_percent = *occupacy_cache_size_reported;
		printf("\n\033[0;31m"); //Set the text to the color red
		printf("Recommended cache size: %ld GiB\n", (*current_cache_size_in_percent * cache_vol_sz) / 100 / 1024 / 1024 / 1024);
		printf("\033[0m"); //Resets the text to default color
	}
	if (recommend_cache_size) {
		uint64_t rd_hits_percent = (100 * req.rd_hits.value) / req.rd_total.value;
		retry = analyze_recommandation(rd_hits_percent, current_cache_size_in_percent);
	}
	return retry;
}

static int str_to_cache_mode(const char *s, ocf_cache_mode_t *cache_mode)
{
	static char *names[] = {"WT", "WB", "WA", "PT", "WI", "WO"};
	static ocf_cache_mode_t modes[] = {
		ocf_cache_mode_wt, ocf_cache_mode_wb, ocf_cache_mode_wa,
		ocf_cache_mode_pt, ocf_cache_mode_wi, ocf_cache_mode_wo
		};
	for (int i = 0; i < ocf_cache_mode_max; i++) {
		if (!strcasecmp(names[i], s)) {
			*cache_mode = modes[i];
			return 0;
		}
	}
	return 1;
}

static int get_cpu_cnt(void)
{
	int cpu_cnt;
	cpu_set_t mask;

	if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
		error("sched_getaffinity");
	}
	cpu_cnt = CPU_COUNT(&mask);

	if (cpu_cnt < 1) {
		error("System CPUs can not be determined\n");
		exit(1);
	}
	printf("cpu_cnt=%d:", cpu_cnt);
	int cnt = 0;
	int f = -1;
	int i = -1;
	do {
		if (CPU_ISSET(++i, &mask)) {
			if (f < 0) {
				printf(" %d", i);
				f = i;
			}
			cnt++;
		} else if (f >= 0) {
			if (f < i - 1) {
				printf("-%d", i - 1);
			}
			f = -1;
		}
	} while (cnt < cpu_cnt);

	if (f < i) {
		printf("-%d\n", i);
	} else {
		printf("\n");
	}
	if (ENVVAR_AFFINITY() && cpu_cnt > 1) {
		cpu_cnt--;	// Leave 1 cpu free for the ocf_sim main thread
	}
	return cpu_cnt;
}

int main(int argc, char* argv[])
{
	printf("GitVersion: %x\n", OCF_SIM_GIT_VERSION);

	static const device_type_t cache_type[] = {
		E_DEVICE_NVME_1,
		E_DEVICE_DDR_1,
		E_DEVICE_DDR_1,
		E_DEVICE_DDR_1,
	};
	signal(SIGPIPE, handler);
	// signal(SIGPIPE, SIG_IGN);
	double cache_vol_sz_in_gib = DEFAULT_CACHE_VOL_SZ_IN_GIB;
	int num_cache_devices = 2;
	int cache_layers = 1;
	int opt;
	int mcpus;
	int num_iterations = 1;
	bool recommend_cache_size = false;
	ocf_cache_line_size_t cache_line_size = ocf_cache_line_size_none;
	ocf_cache_mode_t cache_mode = ocf_cache_mode_none;
	char *swap_info_file = NULL;

	if (envvar_init()) {
		return 1;
	}
	tracefile_init(argc, argv);
	device_init();

	char* help_str = "Usage:\n"
#ifdef TEAM_FEATURES
		"  ocf_sim -t BLKPARSE_FILE [-c cache_size] [-d num_cache_vols] [-l line_size] [-m cache_mode] [-o {table|csv}] [-O OUTFILE] "
		"[-r][-v][-V][-h][-b[FilePath]][-i num_iterations]\n"
#else
		"  ocf_sim -t BLKPARSE_FILE [-c cache_size] [-d num_cache_vols] [-o {table|csv}] [-O OUTFILE] [-r] [-v] [-V] [-h] [-b [FilePath]]\n"
#endif
		"\n"
		"Options:\n"
		"  -t BLKPARSE_FILE   Input file for ocf_sim.  Multiple -t BLKPARSE_FILE could be used and will be processed in order.\n"
		"  -c cache_size      Specify the cache_size in GiB.  Default value is %ld (GiB).\n"
		"  -o {table|csv}     Defines output format for cache statistics.  It can be either \"table\" (default) or \"csv\".\n"
		"  -O OUTFILE         Save OCF cache statistics to OUTFILE, default is stdout\n"
		"  -r                 Recommend cache size.\n"
		"  -v                 Increase ocf_sim verbosity.  Multiple -v could be used to increase verbosity.\n"
		"  -V                 Print ocf_sim version.\n"
		"  -h                 Display this usage message.\n"
		"  -d                 Number of cache volumes in multi-device cache.  The cache_size is divided equally between drives. Default value is 2.\n"
		"  -b FilePath        Create blktrace files (FilePath/BLKPARSE_FILE.blktrace.cpu#).\n"
		"  -s swapInfoFile    A file that contains a list of the swap partitions in the following format: major,minor startSector sizeInSectors\n"
#ifdef TEAM_FEATURES
		"  -l line_size       Cache line size in KB. One of: 4 (default), 8, 16, 32, or 64.\n"
		"  -m cache_mode      One of: WT (default), WB, WI, WA, PT, WO. Case insensitive.\n"
		"  -i num_iterations  Number of iterations to run the loaded BLKPARSE_FILEs.\n"
		"  -L layers          Number of cache layers.\n"
#endif
		;

#ifdef TEAM_FEATURES
	char *shortopts = "c:vrt:Vho:O:l:m:d:b:s:i:L:";
#else
	char *shortopts = "c:vrt:Vho:O:d:b:s:";
#endif

	while ((opt = getopt(argc, argv, shortopts)) != -1) {
		switch (opt) {
		case 'c':
			cache_vol_sz_in_gib = atof(optarg);
			cache_vol_sz = (uint64_t)(cache_vol_sz_in_gib * 1024) * MiB;
			break;
		case 'v':
			verbose++;
			break;
		case 't':
			{
				char* path;
				while ((path = strtok(optarg, ",")) != NULL) {
					tracefile_add(path);
					optarg = NULL;
				}
				break;
			}
		case 'o':
			if (strcasecmp("csv", optarg) == 0) {
				out_format = OUTPUT_FORMAT_CSV;
			}
			else if (strcasecmp("table", optarg) == 0) {
				out_format = OUTPUT_FORMAT_TABLE;
			}
			else {
				printf(help_str, DEFAULT_CACHE_VOL_SZ_IN_GIB);
				exit(1);
			}
			break;

		case 'O':
			strncpy(outfile_name, optarg, OUTFILE_MAX_LEN - 1);
			outfile_name[OUTFILE_MAX_LEN - 1] = '\0';
			print_to_file = true;
			break;

		case 'V':
			printf("GitVersion: %x\n", OCF_SIM_GIT_VERSION);
			exit(0);
			break;

		case 'r':
			recommend_cache_size = true;
			break;

#ifdef TEAM_FEATURES
		case 'l':
			cache_line_size = atoi(optarg) * KiB;
			break;

		case 'm':
			if (str_to_cache_mode(optarg, &cache_mode))
			{
				printf("Illegal cache mode '%s'. Must be one "
					"of: WT, WB, WI, WA, PT, WO\n",
					optarg);
				printf(help_str, DEFAULT_CACHE_VOL_SZ_IN_GIB);
				exit(1);
			}
			break;
		case 'i':
			num_iterations = atoi(optarg);
			break;

		case 'L':
			cache_layers = atoi(optarg);
			if (cache_layers < 1 || cache_layers > ARRAY_SIZE(cache_type)) {
				error("Illegal number of cache layers\n");
			}
			break;
#endif

		case 'd':
			num_cache_devices = atoi(optarg);
			if (num_cache_devices > MAX_SUPPORTED_CACHE_VOLUMES) {
				error("Too many of volumes in multi-device cache\n");
			}
			break;

		case 'b':
			blktrace_set_path(optarg);
			break;

		case 's':
			swap_info_file = optarg;
			break;

		case 'h':
		case '?':
		default:
			printf(help_str, DEFAULT_CACHE_VOL_SZ_IN_GIB);
			exit(1);
		}
	}
	if (tracefile_get_cnt() == 0) {
		printf("\t\t\t=======> BLKPARSE_FILE missing <=======\n");
	}
	setbuf(stdout, NULL);

	mcpus = get_cpu_cnt();
	core_init(swap_info_file);
	if (tracefile_load(mcpus)) {
		goto skip_workload;
	}
	blktrace_init();

	/* Initialize OCF context */
	if (ctx_init(&ctx))
		error("Unable to initialize context\n");

	uint64_t current_cache_size_in_percent = 100;
	bool retry_diffrent_cache_size = true;
	int occupacy_cache_size_reported = 0;
	uint64_t orig_cache_vol_sz = cache_vol_sz;
	FILE* outfile = NULL;
	pthread_t print_to_file_thread = 0;
	print_to_file_thread_data data;

	if (print_to_file) {
		print_to_file_thread = print_to_file_init(&outfile, &data);
	}
	/* Start cache */
	cache_init(cache_layers);
	ocf_cache_t cache = NULL;
	while (retry_diffrent_cache_size && current_cache_size_in_percent) {
		/* Add Caches */
		cache_vol_sz = (current_cache_size_in_percent * orig_cache_vol_sz) / 100;
		cache_vol_sz /= num_cache_devices;
		cache_vol_sz &= ~(PAGE_SIZE - 1);
		top_msla_vol_sz = (cache_layers == 1) ? cache_vol_sz : (cache_vol_sz / 10);
		if (top_msla_vol_sz < OCF_CACHE_SIZE_MIN) {
			top_msla_vol_sz = OCF_CACHE_SIZE_MIN;
		} else {
			top_msla_vol_sz &= ~(uint64_t)(PAGE_SIZE - 1);
		}
		ocf_log_time(0, "initialize cache - num_devices:%d size_per_device: %.2f GiB\n",
			num_cache_devices, cache_vol_sz / 1024.0 / 1024 / 1024);
		for (int i = 0; i < cache_layers; i++) {
			if ((cache = cache_add(mcpus, ctx, num_cache_devices, cache_line_size, cache_mode, cache_type[i])) == NULL) {
				error("Unable to start cache\n");
			}
		}

		ocf_log_time(0, "initialize_core - size: %ld GiB\n", backend_vol_sz / 1024 / 1024 / 1024);
		/* Add cores to the main cache */
		if (core_add_all(ocf_cache_ml_get_main_cache(cache)) < 0) {
			error("Unable to add core\n");
		}
		tracefile_stats();

		/* Do some actual io operations */
		if (tracefile_get_cnt()) {
			perform_workload(num_iterations, mcpus);
		}
		retry_diffrent_cache_size = check_need_to_retry(cache, recommend_cache_size, &current_cache_size_in_percent, &occupacy_cache_size_reported);

		/* Remove Caches */
		cache_remove();
	}
	cache_cleanup();

	if (recommend_cache_size) {
		printf("\n\033[0;31m"); //Set the text to the color red
		uint64_t recommended_cache_size_percent = min(current_cache_size_in_percent + NEXT_ITER_DIFF, 100);
		if ((recommended_cache_size_percent < 100) && occupacy_cache_size_reported) {
			recommended_cache_size_percent = min(recommended_cache_size_percent, occupacy_cache_size_reported);
		}
		printf("Recommended cache size: %ld GiB\n", recommended_cache_size_percent * orig_cache_vol_sz / 100 / 1024 / 1024 / 1024);
		printf("\033[0m"); //Resets the text to default color
	}

	if (print_to_file) {
		print_to_file_end(print_to_file_thread, outfile);
	}

	/* Deinitialize context */
	tracefile_cleanup();
	ctx_cleanup(ctx);

	blktrace_cleanup();
skip_workload:
	core_cleanup();
	ocf_log_time(0, "exit\n");

	return 0;
}
