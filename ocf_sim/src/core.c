/*
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "core.h"

#include <stdint.h>

#include <semaphore.h>

#include "ocf/ocf_core_priv.h"
#include "ocf/ocf_def.h"
#include "ocf/ocf_def_priv.h"
#include "ocf/ocf_mngt.h"
#include "ocf/ocf_types.h"
#include "ocf/ocf_volume.h"
#include "ocf/ocf_ohash.h"
#include "ocf/ocf_swap.h"

#include "ctx.h"
#include "device.h"
#include "trace_file.h"
#include "vol_sim.h"
#include "volume.h"

#define VOL_PREFIX		"core"

#define	OHASH_SIZE		2048
#define OHASH_SECTOR_BITS	(46 - ENV_SECTOR_SHIFT)		/* 64TB in sectors */
#define OHASH_IDX_BITS		(64 - OHASH_SECTOR_BITS)
#define OHASH_IDX_EMPTY_VAL	((1 << OHASH_IDX_BITS) - 1)

#define CORE_LOOP_ALL(_h)	for (core_handle_t _h = core_get_next(NULL); _h; _h = core_get_next(_h))

typedef union {
        struct {
		uint64_t sector:OHASH_SECTOR_BITS;
		uint64_t idx:OHASH_IDX_BITS;
	};
        uint64_t raw;
} ohash_t;

static const ohash_t c_mask = {
	.sector = ~0,	/* mask includes all sector bits */
	.idx = 0,
};

struct core_handle_s {
	struct core_handle_s *next;
	struct ocf_core *core;
	ohash64_handle_t hash;		// Hash table that is used (when parsing the trace) to find the relevant Q of the C
	long last_c_q_idx;		// Index of the request of the last C
	int32_t mi;
	int16_t mj;
};

static core_handle_t s_head = NULL;
static FILE *s_swap_info_fp = NULL;
/*
 * Add core completion callback context. We need this to propagate error code
 * and handle to freshly initialized core object.
 */
typedef struct {
	ocf_core_t *core;
	int *error;
	sem_t sem;
} add_core_context_t;

/* Add core complete callback. Just rewrite args to context structure and
 * up the semaphore.
 */
static void add_core_complete(ocf_cache_t cache, ocf_core_t core, void *priv, int error)
{
	add_core_context_t *context = priv;

	*context->core = core;
	*context->error = error;
	sem_post(&context->sem);
}

static int add_core_to_cache(ocf_cache_t cache, core_handle_t handle, uint idx)
{
	add_core_context_t context;

	/* Initialize completion semaphore */
	int ret = sem_init(&context.sem, 0, 0);
	if (ret) {
		ocf_log(0, "%s\n", "sem_init failed");
		return ret;
	}

	/*
	 * Asynchronous callback will assign core handle to core and error code to ret.
	 */
	context.core = &handle->core;
	context.error = &ret;

	/* Core configuration */
	struct ocf_mngt_core_config core_cfg = { 0 };

	ocf_mngt_core_config_set_default(&core_cfg);

	sprintf(core_cfg.name, "%s%d", VOL_PREFIX, idx);
	core_cfg.volume_type = VOLUME_TYPE;

	if ((ret = ocf_uuid_set_str(&core_cfg.uuid, core_cfg.name)) == 0) {
		/* Add core to cache */
		ocf_mngt_cache_add_core(cache, &core_cfg, add_core_complete, &context);
		sem_wait(&context.sem);
	} else {
		ocf_log(0, "ocf_uuid_set_str(%s) failed\n", core_cfg.name);
	}
	sem_destroy(&context.sem);

	return ret;
}

static void handle_swap_partition(core_handle_t handle)
{
	char line[80];
	int32_t mi;
	int32_t mj;
	uint64_t start;
	uint32_t size;

	if (s_swap_info_fp == NULL ||
			!(handle->core->ocf_classifier & OCF_CLASSIFIER_SWAP)) {
		return;
	}

	rewind(s_swap_info_fp);
	while(fgets(line, sizeof(line), s_swap_info_fp)) {
		if (sscanf(line, "%d,%d %lu %u", &mj, &mi, &start, &size) != 4) {
			error1("%s is an swap info illegal line (mj,mi, start, size)", line);
		}
		if (handle->mj == mj && handle->mi == mi) {
			ocf_swap_add_swap_partition(handle->core, 0, start, size);
			break;
		}
	}
}

// Add all cores to cache
int core_add_all(struct ocf_cache *cache)
{
	uint i = 0;
	// Add all cores to cache
	CORE_LOOP_ALL(handle) {
		ocf_ohash_destroy(&handle->hash);	// We don't need the ohash anymore

		if (add_core_to_cache(cache, handle, ++i)) {
			return -1;
		}
		volsim_init_params_t init_params = {
			.mj = handle->mj,
			.mi = handle->mi,
			.device_type = E_DEVICE_FRONT,
		};
		ocf_volume_t volume = ocf_core_get_front_volume(handle->core);

		ocf_volume_open(volume, NULL);
		volsim_set_init_params(volume, &init_params);

		ocf_core_t lower_core;
		for (ocf_core_t core = ocf_cache_ml_get_highest_core(handle->core); core != NULL; core = lower_core) {
			ocf_volume_t volume = ocf_core_get_volume(core);

			lower_core = ocf_cache_ml_get_lower_core(core);
			if (lower_core == NULL) {
				init_params.mi++;
				init_params.device_type = E_DEVICE_HDD_1;
			} else {
				init_params.mj += 1000;
				init_params.device_type = E_DEVICE_BACK;
			}
			volsim_set_init_params(volume, &init_params);
		}
		ocf_mngt_core_set_seq_cutoff_policy(handle->core, ocf_seq_cutoff_policy_never);
		handle_swap_partition(handle);
	}
	return 0;
}

void core_cleanup(void)
{
	while (s_head) {
		core_handle_t first = s_head;
		s_head = s_head->next;
		free(first);
	}
	if (s_swap_info_fp != NULL) {
		fclose(s_swap_info_fp);
	}
}

ocf_core_t core_get_core(core_handle_t handle)
{
	return handle->core;
}

core_handle_t core_get_handle(int16_t mj, int32_t mi)
{
	CORE_LOOP_ALL(handle) {
		if (handle->mj == mj && handle->mi == mi) {
			return handle;
		}
	}

	return NULL;
}

core_handle_t core_get_next(core_handle_t handle)
{
	return handle ? handle->next : s_head;
}

uint64_t core_get_size(core_handle_t handle)
{
	return ocf_volume_get_length(ocf_core_get_volume(handle->core));
}

long core_get_q_idx(core_handle_t handle, uint64_t sector)
{
	ohash_t hash_item = {
		.raw = ocf_ohash_get(&handle->hash, sector, c_mask.raw)
	};

	if (hash_item.sector != sector || hash_item.idx == OHASH_IDX_EMPTY_VAL) {
		return -1;
	}
	core_set_q_idx(handle, sector, OHASH_IDX_EMPTY_VAL);	// Mark the Q sector as "used"
	long q_idx = (long)(uint64_t)hash_item.idx;
	handle->last_c_q_idx = OCF_MAX(handle->last_c_q_idx, q_idx);

	return q_idx;
}

void core_init(char *swap_info_file)
{
	s_head = NULL;

	if (swap_info_file != NULL &&
			(s_swap_info_fp = fopen(swap_info_file, "r")) == NULL) {
		error1("Swap info file %s doesn't exist", swap_info_file);
	}
}

core_handle_t core_new(int16_t mj, int32_t mi)
{
	core_handle_t handle = calloc(1, sizeof(*handle));
	ocf_ohash_create(NULL, &handle->hash, OHASH_SIZE, "ocf_sim");
	handle->mj = mj;
	handle->mi = mi;
	handle->next = s_head;
	s_head = handle;

	return handle;
}

// Set the Q sector+Index in the hash table
long core_set_q_idx(core_handle_t handle, uint64_t sector, long idx)
{
	ohash_t hash_item = {
		.sector = sector,
		.idx = idx
	};

	ocf_ohash_set(&handle->hash, hash_item.raw, c_mask.raw);

	return handle->last_c_q_idx;
}
