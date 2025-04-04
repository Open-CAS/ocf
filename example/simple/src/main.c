/*
 * Copyright(c) 2019-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>
#include <ocf/ocf.h>
#include "data.h"
#include "ctx.h"
#include "queue_thread.h"

/*
 * Cache private data. Used to share information between async contexts.
 */
struct cache_priv {
	ocf_queue_t mngt_queue;
	ocf_queue_t io_queue;
};

/*
 * Queue ops providing interface for running queue thread in asynchronous
 * way. Optional synchronous kick callback is not provided. The stop()
 * operation is called just before queue is being destroyed.
 */
const struct ocf_queue_ops queue_ops = {
	.kick = queue_thread_kick,
	.stop = queue_thread_stop,
};

/*
 * Simple completion context. As lots of OCF API functions work asynchronously
 * and call completion callback when job is done, we need some structure to
 * share program state with completion callback. In this case we have a
 * variable pointer to propagate error code and a semaphore to signal
 * completion.
 *
 */
struct simple_context {
	int *error;
	sem_t sem;
};

/*
 * Basic asynchronous completion callback. Just propagate error code and
 * up the semaphore.
 */
static void simple_complete(ocf_cache_t cache, void *priv, int error)
{
	struct simple_context *context= priv;

	*context->error = error;
	sem_post(&context->sem);
}

/*
 * Function starting cache and attaching cache device.
 */
int initialize_cache(ocf_ctx_t ctx, ocf_cache_t *cache)
{
	struct ocf_mngt_cache_config cache_cfg = { .name = "cache1" };
	struct ocf_mngt_cache_attach_config attach_cfg = { };
	ocf_volume_t volume;
	ocf_volume_type_t type;
	struct ocf_volume_uuid uuid;
	struct cache_priv *cache_priv;
	struct simple_context context;
	int ret;

	/* Initialize completion semaphore */
	ret = sem_init(&context.sem, 0, 0);
	if (ret)
		return ret;

	/*
	 * Asynchronous callbacks will assign error code to ret. That
	 * way we have always the same variable holding last error code.
	 */
	context.error = &ret;

	/* Cache configuration */
	ocf_mngt_cache_config_set_default(&cache_cfg);
	cache_cfg.metadata_volatile = true;

	/* Cache device (volume) configuration */
	type = ocf_ctx_get_volume_type(ctx, VOL_TYPE);
	ret = ocf_uuid_set_str(&uuid, "cache");
	if (ret)
		goto err_sem;

	ret = ocf_volume_create(&volume, type, &uuid);
	if (ret)
		goto err_sem;

	ocf_mngt_cache_attach_config_set_default(&attach_cfg);
	attach_cfg.device.volume = volume;

	/*
	 * Allocate cache private structure. We can not initialize it
	 * on stack, as it may be used in various async contexts
	 * throughout the entire live span of cache object.
	 */
	cache_priv = malloc(sizeof(*cache_priv));
	if (!cache_priv) {
		ret = -ENOMEM;
		goto err_vol;
	}

	/* Start cache */
	ret = ocf_mngt_cache_start(ctx, cache, &cache_cfg, NULL);
	if (ret)
		goto err_priv;

	/* Assing cache priv structure to cache. */
	ocf_cache_set_priv(*cache, cache_priv);

	/*
	 * Create management queue. It will be used for performing various
	 * asynchronous management operations, such as attaching cache volume
	 * or adding core object. This has to be done before any other
	 * management operation. Management queue is treated specially,
	 * and it may not be used for submitting IO requests. It also will not
	 * be put on the cache stop - we have to put it manually at the end.
	 */
	ret = ocf_queue_create_mngt(*cache, &cache_priv->mngt_queue,
			&queue_ops);
	if (ret) {
		ocf_mngt_cache_stop(*cache, simple_complete, &context);
		sem_wait(&context.sem);
		goto err_priv;
	}

	/* Create queue which will be used for IO submission. */
	ret = ocf_queue_create(*cache, &cache_priv->io_queue, &queue_ops);
	if (ret)
		goto err_cache;

	ret = initialize_threads(cache_priv->mngt_queue, cache_priv->io_queue);
	if (ret)
		goto err_cache;

	/* Attach volume to cache */
	ocf_mngt_cache_attach(*cache, &attach_cfg, simple_complete, &context);
	sem_wait(&context.sem);
	if (ret)
		goto err_cache;

	ocf_volume_destroy(volume);

	return 0;

err_cache:
	ocf_mngt_cache_stop(*cache, simple_complete, &context);
	ocf_queue_put(cache_priv->mngt_queue);
err_priv:
	free(cache_priv);
err_vol:
	ocf_volume_destroy(volume);
err_sem:
	sem_destroy(&context.sem);
	return ret;
}

/*
 * Add core completion callback context. We need this to propagate error code
 * and handle to freshly initialized core object.
 */
struct add_core_context {
	ocf_core_t *core;
	int *error;
	sem_t sem;
};

/* Add core complete callback. Just rewrite args to context structure and
 * up the semaphore.
 */
static void add_core_complete(ocf_cache_t cache, ocf_core_t core,
		void *priv, int error)
{
	struct add_core_context *context = priv;

	*context->core = core;
	*context->error = error;
	sem_post(&context->sem);
}

/*
 * Function adding cache to core.
 */
int initialize_core(ocf_cache_t cache, ocf_core_t *core)
{
	struct ocf_mngt_core_config core_cfg = { };
	struct add_core_context context;
	int ret;

	/* Initialize completion semaphore */
	ret = sem_init(&context.sem, 0, 0);
	if (ret)
		return ret;

	/*
	 * Asynchronous callback will assign core handle to core,
	 * and to error code to ret.
	 */
	context.core = core;
	context.error = &ret;

	/* Core configuration */
	ocf_mngt_core_config_set_default(&core_cfg);
	strcpy(core_cfg.name, "core1");
	core_cfg.volume_type = VOL_TYPE;
	ret = ocf_uuid_set_str(&core_cfg.uuid, "core");
	if (ret)
		goto err_sem;

	/* Add core to cache */
	ocf_mngt_cache_add_core(cache, &core_cfg, add_core_complete, &context);
	sem_wait(&context.sem);

err_sem:
	sem_destroy(&context.sem);

	return ret;
}

/*
 * Callback function called when write completes.
 */
void complete_write(ocf_io_t io, void *priv1, void *priv2, int error)
{
	struct volume_data *data = ocf_io_get_data(io);

	printf("WRITE COMPLETE: (error: %d)\n", error);

	/* Free data buffer and io */
	ctx_data_free(data);
	ocf_io_put(io);
}

/*
 * Callback function called when read completes.
 */
void complete_read(ocf_io_t io, void *priv1, void *priv2, int error)
{
	struct volume_data *data = ocf_io_get_data(io);

	printf("READ COMPLETE (error: %d)\n", error);
	printf("DATA: \"%s\"\n", (char *)data->ptr);

	/* Free data buffer and io */
	ctx_data_free(data);
	ocf_io_put(io);
}

/*
 * Wrapper function for io submition.
 */
int submit_io(ocf_core_t core, struct volume_data *data,
		uint64_t addr, uint64_t len, int dir, ocf_end_io_t cmpl)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_volume_t core_vol = ocf_core_get_front_volume(core);
	struct cache_priv *cache_priv = ocf_cache_get_priv(cache);
	ocf_io_t io;

	/* Allocate new io */
	io = ocf_volume_new_io(core_vol, cache_priv->io_queue, addr, len, dir, 0, 0);
	if (!io)
		return -ENOMEM;

	/* Assign data to io */
	ocf_io_set_data(io, data, 0);
	/* Setup completion function */
	ocf_io_set_cmpl(io, NULL, NULL, cmpl);
	/* Submit io */
	ocf_core_submit_io(io);

	return 0;
}

/*
 * This function simulates actual business logic.
 *
 * It performs following steps:
 * 1. Allocate data buffer for write and write it with example data.
 * 2. Allocate new io, configure it for write, setup completion callback
 *    and perform write to the core.
 * 3. Wait for write io completion (write is handled synchronosly, so no
 *    actual wait is needed, but in real life we would need to use some
 *    synchronization to be sure, that completion function has been already
 *    called). Alternatively we could issue read io from write completion
 *    callback.
 * 4. Allocate data buffer for read.
 * 5. Allocate new io, configure it for read, setup completion callback
 *    and perform read from the core, from the same address where data
 *    was previously written.
 * 6. Print example data in read completion callback.
 *
 * Data buffers and ios are freed in completion callbacks, so there is no
 * need to handle freeing in this function.
 */
void perform_workload(ocf_core_t core)
{
	struct volume_data *data1, *data2;

	/* Allocate data buffer and fill it with example data */
	data1 = ctx_data_alloc(1);
	if (!data1) {
		printf("Error: Unable to allocate data1\n");
		return;
	}
	strcpy(data1->ptr, "This is some test data");
	/* Prepare and submit write IO to the core */
	submit_io(core, data1, 0, 512, OCF_WRITE, complete_write);
	/* After write completes, complete_write() callback will be called. */

	/*
	 * Here we would need to wait until write completes to be sure, that
	 * performing read we retrive written data.
	 */

	/* Allocate data buffer for read */
	data2 = ctx_data_alloc(1);
	if (!data2) {
		printf("Error: Unable to allocate data2\n");
		return;
	}
	/* Prepare and submit read IO to the core */
	submit_io(core, data2, 0, 512, OCF_READ, complete_read);
	/* After read completes, complete_read() callback will be called,
	 * where we print our example data to stdout.
	 */
}

static void remove_core_complete(void *priv, int error)
{
	struct simple_context *context = priv;

	*context->error = error;
	sem_post(&context->sem);
}

int main(int argc, char *argv[])
{
	struct cache_priv *cache_priv;
	struct simple_context context;
	ocf_ctx_t ctx;
	ocf_cache_t cache1;
	ocf_core_t core1;
	int ret;

	/* Initialize completion semaphore */
	ret = sem_init(&context.sem, 0, 0);
	if (ret) {
		printf("Error: Unable to initialize completion semaphore\n");
		goto sem_err;
	}
	context.error = &ret;

	/* Initialize OCF context */
	if (ctx_init(&ctx)) {
		printf("Error: Unable to initialize context\n");
		goto ctx_err;
	}

	/* Start cache */
	if (initialize_cache(ctx, &cache1)) {
		printf("Error: Unable to start cache\n");
		goto cache_err;
	}

	/* Add core */
	if (initialize_core(cache1, &core1)) {
		printf("Error: Unable to add core\n");
		goto core_err;
	}

	/* Do some actual io operations */
	perform_workload(core1);

	/* Remove core from cache */
	ocf_mngt_cache_remove_core(core1, remove_core_complete, &context);
	sem_wait(&context.sem);
	if (ret) {
		printf("Error: Unable to remove core\n");
		goto core_err;
	}

	/* Stop cache */
	ocf_mngt_cache_stop(cache1, simple_complete, &context);
	sem_wait(&context.sem);
	if (ret) {
		printf("Error: Unable to stop cache\n");
	}

core_err:
	cache_priv = ocf_cache_get_priv(cache1);

	/* Put the management queue */
	ocf_queue_put(cache_priv->mngt_queue);

	free(cache_priv);
cache_err:
	/* Deinitialize context */
	ctx_cleanup(ctx);
ctx_err:
	/* Destroy completion semaphore */
	sem_destroy(&context.sem);
sem_err:
	return ret;
}
