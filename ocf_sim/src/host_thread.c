/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "host_thread.h"

#define _GNU_SOURCE
#include <memory.h>
#include <stddef.h>
#include <stdio.h>

#include <pthread.h>
#include <semaphore.h>

#include "ocf/ocf_io.h"
#include "ocf/ocf_queue_priv.h"
#include "ocf/ocf_blktrace.h"
#include "host_io.h"
#include "data.h"
#include "ctx.h"
#include "cache.h"
#include "core.h"
#include "envvar.h"
#include "vol_sim.h"

#define	MAX_SUPPORTED_CPUS	256
#define	STATUS_BITMAP_SHIFT	6
#define	STATUS_BITMAP_IDX(_cpu)	((_cpu) >> STATUS_BITMAP_SHIFT)
#define	STATUS_BITMAP_MASK	((1 << STATUS_BITMAP_SHIFT) - 1)
#define	STATUS_BITMAP_BIT(_cpu)	((_cpu) & STATUS_BITMAP_MASK)

typedef struct {
	pthread_t thread_id;
	sem_t sem;
	long last_hio_idx;
	int cpu;
	volatile bool active;
} HostThread;

typedef struct hostthread_handle_s {
	void *sched;
	volatile uint64_t status_bitmap[STATUS_BITMAP_IDX(MAX_SUPPORTED_CPUS - 1)];
	env_atomic64 *comp_cnt;
	int mcpus;
	HostThread host_thread_array[0];		// Must be last
} *hostthread_handle_t ;

#define	OFFSETOF_HOST_THREAD_ARRAY	offsetof(struct hostthread_handle_s, host_thread_array)
#define	HANDLE(_self)	((hostthread_handle_t)((uint8_t *)((_self) - (_self)->cpu) - OFFSETOF_HOST_THREAD_ARRAY))

static void* hostthread_run(void* arg);

// Create a thread and bind it to a cpu
static void ht_create(HostThread *self, int cpu, int aff_cpu)
{
	if (sem_init(&self->sem, 0, 0)) {
		printf("%s#%d %s: sem_init failed for cpu %d\n", __FILE__, __LINE__, __func__, cpu);
		exit(1);
	}
	self->cpu = cpu;
	self->last_hio_idx = -1;

	if (pthread_create(&self->thread_id, NULL, hostthread_run, self)) {
		printf("%s#%d %s: pthread_create failed for cpu %d\n", __FILE__, __LINE__, __func__, cpu);
		exit(1);
	}

	char hostthread_name[MAX_LENGTH_PTHREAD_NAME];
	sprintf(hostthread_name, "ocf_sim:app%03d", cpu & 0xFF);
	pthread_setname_np(self->thread_id, hostthread_name);

	if (ENVVAR_AFFINITY()) {
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		CPU_SET(aff_cpu, &cpuset);

		if (pthread_setaffinity_np(self->thread_id, sizeof(cpuset), &cpuset) != 0) {
			printf("pthread_setaffinity_np  - failed to bind %s to cpu %d\n", hostthread_name, aff_cpu);
			exit(1);
		}
	}
}

static void ht_destroy(HostThread *self)
{
	self->active = false;
	sem_post(&self->sem);
	pthread_join(self->thread_id, NULL);
	sem_destroy(&self->sem);
}

static inline void update_status_bit(hostthread_handle_t handle, int cpu, bool set)
{
	uint idx = STATUS_BITMAP_IDX(cpu);
	uint bit = STATUS_BITMAP_BIT(cpu);
	uint64_t mask = (1 << bit);
	uint64_t new_val;
	uint64_t old_val;
	uint64_t val = handle->status_bitmap[idx];
	do {
		new_val = set ? (val | mask) : (val & ~mask);
		old_val = val;
	} while ((val =	__sync_val_compare_and_swap (&handle->status_bitmap[idx], old_val, new_val)) != old_val);
}

void hostthread_trigger(hostthread_handle_t handle, int cpu)
{
	HostThread *self = &handle->host_thread_array[cpu];
	int sval;

	if (sem_getvalue(&self->sem, &sval) || sval <= 0) {
		sem_post(&self->sem);	// Trigger thread on need
	}
}

/*
 * Callback function called when io completes.
 */
static void submit_io(HostThread* self, HostIO *hio, void *data,
	uint64_t addr, uint64_t len, int dir, ocf_end_io_t cmpl)
{
	ocf_core_t core = core_get_core(hio->core_handle);
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_queue_t q = cache_get_queue(cache, self->cpu);
	int orig_dir = dir;
	dir = (dir == OCF_DISCARD) ? OCF_WRITE : dir;
	/* Allocate new io */
	ocf_io_t io = ocf_volume_new_io(ocf_core_get_front_volume(core), q, addr, len, dir, 0, 0);
	if (!io) {
		printf("ocf_volume_new_io() failed\n");
		exit(1);
	}

	/* Assign data to io */
	ocf_io_set_data(io, data, 0);
	/* Setup completion function */
	ocf_io_set_cmpl(io, self, NULL, cmpl);
	/* Submit io */
	io->io.ocf_io_blktrace.priv = (void *)hio;
	OCF_BLKTRACE_NEW_IO(io);
	if (orig_dir == OCF_DISCARD) {
		ocf_core_submit_discard(io);
	} else {
		ocf_core_submit_io(io);
	}
	if (env_atomic_read(&q->io_no)) {
		ocf_queue_kick(q, true);
	}
}

void complete_io(ocf_io_t io, void *priv1, void *priv2, int error)
{
	volsim_orig_io_completed(io);

	/* Free data buffer and io */
	ocf_ctx_data_free1(ocf_io_get_data(io));
	ocf_io_put(io);

	// Update database
	HostThread *self = (HostThread*)priv1;
	env_atomic64_inc(HANDLE(self)->comp_cnt);
}

static void execute_io(HostThread *self, HostIO *hio)
{
	struct volume_data* data1;
	long size = hio->size;
	long offs = hio->offset;
	long drct = hio->drc;
	uint64_t core_size = core_get_size(hio->core_handle);

	if ((offs + size - 1) >= core_size) {
		if (offs >= core_size) {
			ocf_log_timestamp(0, "skipping %s %ld sectors %s %ld\n", drct ? "writing" : "reading",
				size, drct ? "to" : "from", offs);
			return;
		}
		size = core_size - offs;
		ocf_log_timestamp(3, "%s %ld sectors %s %ld - instead\n", drct ? "writing" : "reading",
			size, drct ? "to" : "from", offs);
	}
	/* Allocate data buffer and fill it with example data */
	if ((data1 = ocf_ctx_data_alloc1(0)) == NULL) {
		printf("Unable to allocate data1\n");
		exit(1);
	}
	/* Prepare and submit write IO to the core */
	size <<= ENV_SECTOR_SHIFT;
	offs <<= ENV_SECTOR_SHIFT;
	submit_io(self, hio, data1, offs, size, drct, complete_io);
}

static void *hostthread_run(void *arg)
{
	HostThread *self = (HostThread *)arg;
	hostthread_handle_t handle = HANDLE(self);

	self->active = true;

	while (self->active) {
		scheduler_directive_t directive;
		HostIO *hio = scheduler_next_hio(handle->sched, self->cpu, &self->last_hio_idx, &directive);

		switch (directive) {
			case E_SCHEDULER_EXEC_IO:
				ENV_BUG_ON(hio == NULL);
				update_status_bit(handle, self->cpu, true);
				execute_io(self, hio);
				break;
			case E_SCHEDULER_YIELD:
				sched_yield();
				break;
			case E_SCHEDULER_DONE:
				update_status_bit(handle, self->cpu, false);
			case E_SCHEDULER_WAIT:
				if (sem_wait(&self->sem)) {
					printf("%s#%d %s: sem_wait failed for cpu %d\n", __FILE__, __LINE__, __func__, self->cpu);
					exit(1);
				}
				break;
			default:
				ENV_BUG();
		}
	}
	update_status_bit(handle, self->cpu, false);

	return NULL;
}

bool hostthread_active(hostthread_handle_t handle)
{
	uint i = (handle->mcpus - 1) >> 6;	// Each status_bitmap entry supports 64 CPUs
	do {
		if (handle->status_bitmap[i]) {
			return true;
		}
	} while(i--);
	return false;
}

void hostthread_start(hostthread_handle_t handle)
{
	for (int i = 0; i < handle->mcpus; i++) {
		handle->host_thread_array[i].last_hio_idx = -1;
	}
}

// Init
hostthread_handle_t hostthread_init(void *sched, int mcpus, env_atomic64 *cnt)
{
	size_t size = OFFSETOF_HOST_THREAD_ARRAY + mcpus * sizeof(HostThread);
	hostthread_handle_t handle = malloc(size);

	if (handle == NULL) {
		printf("%s#%d %s: malloc(%lu) failed\n", __FILE__, __LINE__, __func__, size);
		exit(1);
	}
	memset(handle, 0, size);
	if (sizeof(handle->status_bitmap) * 8 < mcpus) {
		printf("Need to enlarge handle->status_bitmap to support more than %lu cpus\n", sizeof(handle->status_bitmap) * 8);
		exit(1);
	}
	handle->sched = sched;
	handle->mcpus = mcpus;
	handle->comp_cnt = cnt;

	cpu_set_t mask;
	if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
		printf("sched_getaffinity");
		exit(1);
	}
	for (int i = 0, j = 0; i < mcpus; i++, j++) {
		while (!CPU_ISSET(j, &mask))
			j++;
		ht_create(&handle->host_thread_array[i], i, j);
	}

	return handle;
}

// Cleanup
void hostthread_cleanup(hostthread_handle_t *phandle)
{
	hostthread_handle_t handle = *phandle;
	for (int i = 0; i < handle->mcpus; i++) {
		ht_destroy(&handle->host_thread_array[i]);
	}
	free(handle);
	*phandle = NULL;
}
