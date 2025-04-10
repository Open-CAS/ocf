/*
 * Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "cache.h"

#include <stdint.h>
#include <time.h>

#include <semaphore.h>

#include "ocf/ocf_cache.h"
#include "ocf/ocf_cache_priv.h"
#include "ocf/ocf_core_priv.h"
#include "ocf/ocf_def.h"
#include "ocf/ocf_mngt.h"
#include "ocf/ocf_queue.h"
#include "ocf/ocf_queue_priv.h"
#include "ocf/ocf_types.h"
#include "ocf/ocf_volume.h"

#include "ctx.h"
#include "device.h"
#include "queue_thread.h"
#include "vol_sim.h"
#include "volume.h"

#define NAME_PREFIX		"cache"
#define LOWER_CACHE_ON_INIT()	(s_head ? ocf_cache_ml_get_lowest_cache(s_head->cache) : NULL)

typedef struct {
	int error;
	sem_t *sem;
} context_t;

typedef struct {
	ocf_queue_t mngt_queue;
	ocf_queue_t *io_queue;
} priv_t ;

struct _cache_s {
	ocf_cache_t cache;
	priv_t priv;
	struct _cache_s *next;
	bool composite;
	int idx;
};

static int s_cache_layers = 0;
static int s_mcpus = 0;
static cache_handle_t s_head = NULL;
static sem_t s_sem;

static void complete(ocf_cache_t cache, void *priv, int error)
{
	context_t *context = priv;

	context->error = error;
	sem_post(context->sem);
}

static void complete_add_upper(ocf_cache_t cache, ocf_cache_t upper_cache, void *priv, int error)
{
	context_t *context = priv;

	context->error = error;
	sem_post(context->sem);
}

static void _attach_cache(ocf_cache_t cache, ocf_volume_t volume)
{
	struct ocf_mngt_cache_attach_config attach_cfg = { 0 };

	ocf_mngt_cache_attach_config_set_default(&attach_cfg);
	attach_cfg.device.volume = volume;
	attach_cfg.allow_override_defaults = true;

	context_t context = { .sem = &s_sem };

	ocf_mngt_cache_attach(cache, &attach_cfg, complete, &context);
	sem_wait(context.sem);
	if (context.error) {
		error1("ocf_mngt_cache_attach failed (error = %d)", context.error);
	}
}

/* Cache device (volume) configuration */
static ocf_composite_volume_t create_volume(cache_handle_t item, ocf_ctx_t ctx, int num_comp_devices)
{
	ocf_composite_volume_t composite_volume;
	struct ocf_volume_uuid uuid;

	if (ocf_composite_volume_create(&composite_volume, ctx)) {
		error("ocf_composite_volume_create failed");
	}

	ocf_volume_type_t type = ocf_ctx_get_volume_type(ctx, VOLUME_TYPE);
	char *comp_vol_name = malloc(OCF_VOLUME_UUID_MAX_SIZE);
	if (comp_vol_name == NULL) {
		error("Failed on malloc of UUID\n");
	}
	comp_vol_name[0] = '\0';

	for (int i = 1; i <= num_comp_devices; i++) {
		char sub_vol_name[OCF_VOLUME_UUID_MAX_SIZE];

		sprintf(sub_vol_name, "%s%d.%d", NAME_PREFIX, item->idx, i);
		ocf_uuid_set_str(&uuid, sub_vol_name);

		if (ocf_composite_volume_add(composite_volume, type, &uuid, NULL)) {
			error("ocf_composite_volume_add failed");
		}
		strcat(comp_vol_name, sub_vol_name);
		if (i != num_comp_devices) {
			strcat(comp_vol_name, ",");
		}
	}
	ocf_uuid_set_str(&uuid, comp_vol_name);
	ocf_composite_volume_set_uuid(composite_volume, &uuid, true);

	return composite_volume;
}

static void set_queues(int mcpus, ocf_cache_t cache)
{
	static const struct ocf_queue_ops queue_ops = {	// Queue ops providing interface for running queue thread in asynchronous way.
		.kick = queue_thread_kick,		// Optional synchronous kick callback is not provided.
		.stop = queue_thread_stop,		// The stop() operation is called just before queue is being destroyed.
	};
	priv_t *cache_priv = (priv_t *)ocf_cache_get_priv(cache);

	/*
	 * Create management queue. It will be used for performing various
	 * asynchronous management operations, such as attaching cache volume
	 * or adding core object. This has to be done before any other
	 * management operation. Management queue is treated specially,
	 * and it may not be used for submitting IO requests. It also will not
	 * be put on the cache stop - we have to put it manually at the end.
	 */
	if (ocf_queue_create_mngt(cache, &cache_priv->mngt_queue, &queue_ops)) {
		error("ocf_queue_create failed");
	}

	if (s_head == NULL) {
		cache_priv->io_queue = malloc(mcpus * sizeof(*(cache_priv->io_queue)));
		if (!cache_priv->io_queue) {
			error("malloc failed");
		}
		for (int i = 0; i < mcpus; i++) {
			/* Create queue which will be used for IO submission. */
			if (ocf_queue_create(cache, &cache_priv->io_queue[i], &queue_ops)) {
				error("ocf_queue_create failed");
			}
		}
	} else {
		cache_priv->io_queue = NULL;
	}

	if (initialize_threads(cache_priv->mngt_queue, cache_priv->io_queue, mcpus)) {
		error("initialize_threads failed");
	}

	s_mcpus = mcpus;
}

static ocf_cache_t _start_cache(ocf_ctx_t ctx, ocf_cache_line_size_t cache_line_size,
				ocf_cache_mode_t cache_mode, int idx)
{
	struct ocf_mngt_cache_config cache_cfg;
	ocf_cache_t lower_cache = LOWER_CACHE_ON_INIT();

	sprintf(cache_cfg.name, "%s%d", NAME_PREFIX, idx);
	ocf_mngt_cache_config_set_default(&cache_cfg);

	if (cache_line_size != ocf_cache_line_size_none) {
		cache_cfg.cache_line_size = cache_line_size;
		cache_cfg.allow_override_defaults = true;
	}
	if (cache_mode != ocf_cache_mode_none) {
		cache_cfg.cache_mode = cache_mode;
		cache_cfg.allow_override_defaults = true;
	}
	if (idx) {
		cache_cfg.ocf_prefetcher = 0;
		cache_cfg.allow_override_defaults = true;
	}
	ocf_cache_t cache = NULL;
	if (ocf_mngt_cache_start(ctx, &cache, &cache_cfg, NULL)) {
		error("ocf_mngt_cache_start failed");
	}
	// In Multi-SLA - Connect upper cache to the lowest one.
	if (lower_cache != NULL) {
		context_t context = { .sem = &s_sem };
		ocf_mngt_cache_ml_add_cache(lower_cache, cache, complete_add_upper, &context);
		sem_wait(context.sem);
		if (context.error) {
			error1("ocf_mngt_cache_ml_add_cache failed (error = %d)", context.error);
		}
	}

	return cache;
}

// Add a new cache device
ocf_cache_t cache_add(int mcpus, ocf_ctx_t ctx, int num_comp_devices, ocf_cache_line_size_t cache_line_size,
			ocf_cache_mode_t cache_mode, device_type_t cache_type)
{
	// Allocate a new cache item
	cache_handle_t item = (cache_handle_t )malloc(sizeof(*item));

	if (item == NULL) {
		error1("malloc(%lu) failed", sizeof(*item));
	}

	// Start the Cache
	item->idx = s_head ? s_head->idx - 1 : s_cache_layers - 1;
	item->cache = _start_cache(ctx, cache_line_size, cache_mode, item->idx);

	ocf_cache_set_priv(item->cache, &item->priv);

	// Create cache queues and assign them to the cache
	set_queues(mcpus, item->cache);

	volsim_init_params_t init_params = {
		.mj = item->idx * 1000,
		.mi = 0,
		.device_type = E_DEVICE_CACHE	// Assume composite
	};

	// Composite Cache
	if (num_comp_devices > 1) {
		item->composite = true;

		// Create volume and attach it to cache
		ocf_composite_volume_t composite_volume = create_volume(item, ctx, num_comp_devices);

		// Set the volsim init parameters
		volsim_set_init_params(composite_volume, &init_params);
		init_params.device_type = cache_type;

		for (int i = 0; i < num_comp_devices; i++) {
			ocf_volume_t volume = ocf_composite_volume_get_subvolume_by_index(composite_volume, i);
			init_params.mi++;
			volsim_set_init_params(volume, &init_params);
		}

		_attach_cache(item->cache, composite_volume);
		ocf_composite_volume_destroy(composite_volume);

	// Single Cache Volume
	} else {
		item->composite = false;

		ocf_volume_t volume;
		ocf_volume_type_t type = ocf_ctx_get_volume_type(ctx, VOLUME_TYPE);
		struct ocf_volume_uuid uuid;
		char *vol_name = malloc(OCF_VOLUME_UUID_MAX_SIZE);
		if (vol_name == NULL) {
			error("Failed on malloc of UUID\n");
		}
		sprintf(vol_name, "%s%d", NAME_PREFIX, item->idx);
		ocf_uuid_set_str(&uuid, vol_name);
		ocf_volume_create(&volume, type, &uuid);
		ocf_volume_set_uuid(volume, &uuid);
		init_params.device_type = cache_type;
		volsim_set_init_params(volume, &init_params);
		_attach_cache(item->cache, volume);
		ocf_volume_destroy(volume);
	}

	item->next = s_head;
	s_head = item;

	return item->cache;
}

void cache_cleanup(void)
{
	cache_handle_t item = s_head;
	while (item) {
		cache_handle_t next = item->next;
		if (item->priv.io_queue != NULL) {
			free(item->priv.io_queue);
		}
		free(item);
		item = next;
	}
	s_head = NULL;
	sem_destroy(&s_sem);
}

ocf_cache_t cache_get_cache(cache_handle_t handle)
{
	return (handle == NULL) ? NULL : handle->cache;
}

ocf_core_t cache_get_core(cache_handle_t handle, int *core_id)
{
	struct ocf_cache *cache = handle->cache;
	struct ocf_core *core = NULL;

	for (int id = *core_id; id < OCF_CORE_MAX; id++) {
		core = &cache->core[id];
		if (core->added) {
			*core_id = id;
			return core;
		}
	}
	*core_id = OCF_CORE_MAX;

	return NULL;
}

int cache_get_idx(cache_handle_t handle)
{
	return handle->idx;
}

cache_handle_t cache_get_next(cache_handle_t handle)
{
	return (handle == NULL) ? s_head : handle->next;
}

ocf_queue_t cache_get_queue(ocf_cache_t cache, int cpu)
{
	assert(cpu < s_mcpus);
	cache = ocf_cache_ml_get_lowest_cache(cache);
	return ((priv_t *)ocf_cache_get_priv(cache))->io_queue[cpu];
}

void cache_init(int cache_layers)
{
	if (sem_init(&s_sem, 0, 0)) {
		error("sem_init failed\n");
	}

	s_cache_layers = cache_layers;
	s_head = NULL;
}

bool cache_is_composite(cache_handle_t handle)
{
	return (handle == NULL) ? false : handle->composite;
}

// This function runs on all caches and on all the cache Qs and
// kicks the first Q that is not empty
// This function is called by the scheduler in polling mode thats why
// kicking one Q each time is enough
void cache_kick_next_q(void)
{
	static cache_handle_t item = NULL;
	static uint cpu = 0;
	ocf_queue_t q;

	if (s_head == NULL) {
		return;
	}
	if (item == NULL) {
		item = s_head;
	}

	cache_handle_t item_init = item;
	uint cpu_init = cpu;
	do {
		if (cpu >= s_mcpus) {
			cpu = 0;
			item = item->next;
			if (item == NULL) {
				item = s_head;
			}
		}
		if (item_init == item && cpu_init == cpu) {
			return;
		}
		q = cache_get_queue(item->cache, cpu++);
	} while (env_atomic_read(&q->io_no) == 0);

	ocf_queue_kick(q, true);
}

void cache_remove(void)
{
	// Stop lowest cache - it will stop all other caches
	context_t context = { .sem = &s_sem };
	struct timespec ts;

	ocf_mngt_cache_stop(ocf_cache_ml_get_main_cache(s_head->cache), complete, &context);

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 15;
	if (sem_timedwait(context.sem, &ts)) {
		ocf_log(0, "%s:%d(%s): sem_timedwait failed, errno=%d\n", __FILE__, __LINE__, __func__, errno);
	}

	while (s_head) {
		cache_handle_t next = s_head->next;
		ocf_queue_put(s_head->priv.mngt_queue);
		if (s_head->priv.io_queue != NULL) {
			free(s_head->priv.io_queue);
		}
		free(s_head);
		s_head = next;
	}
}
