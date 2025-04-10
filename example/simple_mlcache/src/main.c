/*
 * Copyright(c) 2019-2022 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
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
#include "ocf/ocf_mngt.h"
#include "ocf/ocf_types.h"
#include "queue_thread.h"


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

static void cache_stop_end(ocf_cache_t cache, void *priv, int error)
{
	/* do nothing */
}

static void complete_add_upper(ocf_cache_t lower_cache, ocf_cache_t upper_cache,
		void *priv, int err)
{
	simple_complete(upper_cache, priv, err);
}

static int ocf_cache_ml_create(ocf_ctx_t ctx, ocf_cache_t *uc, ocf_cache_t *lc,
		struct ocf_mngt_cache_config *upper_cfg,
		struct ocf_mngt_cache_config *lower_cfg)
{
	ocf_cache_t upper_cache = NULL;
	ocf_cache_t lower_cache = NULL;
	int result;
	struct simple_context context;

	/* Initialize completion semaphore */
	result = sem_init(&context.sem, 0, 0);
	if (result)
		return result;

	result = ocf_mngt_cache_start(ctx, &lower_cache, lower_cfg, NULL);
	if (result)
		goto err;

	result = ocf_mngt_cache_start(ctx, &upper_cache, upper_cfg, NULL);
	if (result)
		goto err;

	*uc = upper_cache;
	*lc = lower_cache;
	return 0;

err:
	if (upper_cache != NULL)
		ocf_mngt_cache_stop(upper_cache, cache_stop_end, NULL);
	if (lower_cache != NULL)
		ocf_mngt_cache_stop(lower_cache, cache_stop_end, NULL);
	return result;
}

/*
 * Cache private data. Used to share information between async contexts.
 */
struct cache_priv {
	ocf_queue_t lmngt_queue;
	ocf_queue_t umngt_queue;
	ocf_queue_t lio_queue;
	ocf_queue_t uio_queue;
};

/*
 * Helper function for error handling.
 */
void error(char *msg)
{
	printf("ERROR: %s", msg);
	exit(1);
}

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
 * Function starting cache and attaching cache device.
 */
int initialize_cache(ocf_ctx_t ctx, ocf_cache_t *upper_cache,
		ocf_cache_t *lower_cache)
{
	struct ocf_mngt_cache_config lower_cache_cfg = { .name = "lower_cache" };
	struct ocf_mngt_cache_config upper_cache_cfg = { .name = "upper_cache" };
	struct ocf_mngt_cache_attach_config lower_attach_cfg = { };
	struct ocf_mngt_cache_attach_config upper_attach_cfg = { };
	ocf_volume_t volume1, volume2;
	ocf_volume_type_t type;
	struct ocf_volume_uuid uuid1, uuid2;
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

	/* Cache configurations */
	ocf_mngt_cache_config_set_default(&lower_cache_cfg);
	lower_cache_cfg.metadata_volatile = true;
	ocf_mngt_cache_config_set_default(&upper_cache_cfg);
	upper_cache_cfg.metadata_volatile = true;


	/* Cache devices (volumes) configuration */
	type = ocf_ctx_get_volume_type(ctx, VOL_TYPE);

	ret = ocf_uuid_set_str(&uuid1, "cache1");
	if (ret)
		goto err_sem;
	ret = ocf_volume_create(&volume1, type, &uuid1);
	if (ret)
		goto err_sem;

	ret = ocf_uuid_set_str(&uuid2, "cache2");
	if (ret)
		goto err_vol1;
	ret = ocf_volume_create(&volume2, type, &uuid2);
	if (ret)
		goto err_vol1;

	ocf_mngt_cache_attach_config_set_default(&lower_attach_cfg);
	lower_attach_cfg.device.volume = volume1;
	ocf_mngt_cache_attach_config_set_default(&upper_attach_cfg);
	upper_attach_cfg.device.volume = volume2;

	/*
	 * Allocate cache private structure. We can not initialize it
	 * on stack, as it may be used in various async contexts
	 * throughout the entire live span of cache object.
	 */
	cache_priv = malloc(sizeof(*cache_priv));
	if (!cache_priv) {
		ret = -ENOMEM;
		goto err_vol2;
	}
	cache_priv->lmngt_queue = cache_priv->umngt_queue =
		cache_priv->lio_queue = cache_priv->uio_queue = NULL;

	/* Start cache */
	ret = ocf_cache_ml_create(ctx, upper_cache, lower_cache, &upper_cache_cfg, &lower_cache_cfg);
	if (ret)
		goto err_priv;

	/* Assign cache priv structure to cache. */
	ocf_cache_set_priv(*lower_cache, cache_priv);
	ocf_cache_set_priv(*upper_cache, cache_priv);

	/*
	 * Create management queues. They will be used for performing various
	 * asynchronous management operations, such as attaching cache volume
	 * or adding core object. This has to be done before any other
	 * management operation. Management queue is treated specially,
	 * and it may not be used for submitting IO requests. It also will not
	 * be put on the cache stop - we have to put it manually at the end.
	 */
	ret = ocf_queue_create_mngt(*lower_cache, &cache_priv->lmngt_queue,
			&queue_ops);
	if (ret) {
		ocf_mngt_cache_stop(*lower_cache, simple_complete, &context);
		sem_wait(&context.sem);
		ocf_mngt_cache_stop(*upper_cache, simple_complete, &context);
		sem_wait(&context.sem);
		goto err_priv;
	}
	ret = ocf_queue_create_mngt(*upper_cache, &cache_priv->umngt_queue,
			&queue_ops);
	if (ret) {
		ocf_mngt_cache_stop(*lower_cache, simple_complete, &context);
		sem_wait(&context.sem);
		ocf_mngt_cache_stop(*upper_cache, simple_complete, &context);
		sem_wait(&context.sem);
		ocf_queue_put(cache_priv->lmngt_queue);
		goto err_priv;
	}

	/* Create queues which will be used for IO submission. */
	ret = ocf_queue_create(*lower_cache, &cache_priv->lio_queue, &queue_ops);
	if (ret)
		goto err_cache;
	ret = ocf_queue_create(*upper_cache, &cache_priv->uio_queue, &queue_ops);
	if (ret)
		goto err_cache;

	ret = initialize_threads(cache_priv->lmngt_queue, cache_priv->lio_queue);
	if (ret)
		goto err_cache;
	ret = initialize_threads(cache_priv->umngt_queue, cache_priv->uio_queue);
	if (ret)
		goto err_cache;

	/* Attach volumes to caches */
	ocf_mngt_cache_attach(*lower_cache, &lower_attach_cfg, simple_complete, &context);
	sem_wait(&context.sem);
	if (ret)
		goto err_cache;

	ocf_mngt_cache_attach(*upper_cache, &upper_attach_cfg, simple_complete, &context);
	sem_wait(&context.sem);
	if (ret)
		goto err_cache;

	ocf_mngt_cache_ml_add_cache(*lower_cache, *upper_cache, complete_add_upper, &context);
	sem_wait(&context.sem);

	ocf_volume_destroy(volume2);
	ocf_volume_destroy(volume1);

	return 0;

err_cache:
	ocf_mngt_cache_stop(*upper_cache, simple_complete, &context);
	ocf_mngt_cache_stop(*lower_cache, simple_complete, &context);
	ocf_queue_put(cache_priv->umngt_queue);
	ocf_queue_put(cache_priv->lmngt_queue);
err_priv:
	free(cache_priv);
err_vol2:
	ocf_volume_destroy(volume2);
err_vol1:
	ocf_volume_destroy(volume1);
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
	io = ocf_volume_new_io(core_vol, cache_priv->uio_queue, addr, len, dir, 0, 0);
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
	if (!data1)
		error("Unable to allocate data1\n");
	strcpy(data1->ptr, "This is some test data");
	/* Prepare and submit write IO to the core */
	submit_io(core, data1, 0, 4096, OCF_WRITE, complete_write);
	/* After write completes, complete_write() callback will be called. */

	/*
	 * Here we would need to wait until write completes to be sure, that
	 * performing read we retrive written data.
	 */

	/* Allocate data buffer for read */
	data2 = ctx_data_alloc(1);
	if (!data2)
		error("Unable to allocate data2\n");
	/* Prepare and submit read IO to the core */
	submit_io(core, data2, 0, 4096, OCF_READ, complete_read);
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
	ocf_cache_t upper_cache;
	ocf_cache_t lower_cache;
	ocf_core_t core1;
	int ret;

	/* Initialize completion semaphore */
	ret = sem_init(&context.sem, 0, 0);
	if (ret)
		error("Unable to initialize completion semaphore\n");
	context.error = &ret;

	/* Initialize OCF context */
	if (ctx_init(&ctx))
		error("Unable to initialize context\n");

	/* Start cache */
	if (initialize_cache(ctx, &upper_cache, &lower_cache))
		error("Unable to start cache\n");

	/* Add core */
	if (initialize_core(lower_cache, &core1))
		error("Unable to add core\n");

	/* Do some actual io operations */
	perform_workload(core1);

	/* Remove core from cache */
	ocf_mngt_cache_remove_core(core1, remove_core_complete, &context);
	sem_wait(&context.sem);
	if (ret)
		error("Unable to remove core\n");

	/* Stop cache */
	ocf_mngt_cache_stop(lower_cache, simple_complete, &context);
	sem_wait(&context.sem);
	if (ret)
		error("Unable to stop cache_ml\n");

	cache_priv = ocf_cache_get_priv(upper_cache);

	/* Put the management queues */
	ocf_queue_put(cache_priv->umngt_queue);
	ocf_queue_put(cache_priv->lmngt_queue);

	free(cache_priv);

	/* Deinitialize context */
	ctx_cleanup(ctx);

	/* Destroy completion semaphore */
	sem_destroy(&context.sem);

	return 0;
}
