/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <stdio.h>
#include <stdlib.h>
#include <ocf/ocf.h>
#include "data.h"
#include "ctx.h"

/*
 * Helper function for error handling.
 */
void error(char *msg)
{
	printf("ERROR: %s", msg);
	exit(1);
}

/*
 * Function starting cache and attaching cache device.
 */
int initialize_cache(ocf_ctx_t ctx, ocf_cache_t *cache)
{
	struct ocf_mngt_cache_config cache_cfg = { };
	struct ocf_mngt_cache_device_config device_cfg = { };
	int ret;

	/* Cache configuration */
	cache_cfg.backfill.max_queue_size = 65536;
	cache_cfg.backfill.queue_unblock_size = 60000;
	cache_cfg.cache_line_size = ocf_cache_line_size_4;
	cache_cfg.cache_mode = ocf_cache_mode_wt;
	cache_cfg.metadata_volatile = true;
	cache_cfg.io_queues = 1;
	cache_cfg.name = "cache1";

	/* Cache deivce (data object) configuration */
	device_cfg.data_obj_type = OBJ_TYPE;
	device_cfg.cache_line_size = ocf_cache_line_size_4;
	ret = ocf_uuid_set_str(&device_cfg.uuid, "cache");
	if (ret)
		return ret;

	/* Start cache */
	ret = ocf_mngt_cache_start(ctx, cache, &cache_cfg);
	if (ret)
		return ret;

	/* Attach data object to cache */
	ret = ocf_mngt_cache_attach(*cache, &device_cfg);
	if (ret) {
		ocf_mngt_cache_stop(*cache);
		return ret;
	}

	return 0;
}

/*
 * Function adding cache to core.
 */
int initialize_core(ocf_cache_t cache, ocf_core_t *core)
{
	struct ocf_mngt_core_config core_cfg = { };
	int ret;

	/* Core configuration */
	core_cfg.data_obj_type = OBJ_TYPE;
	core_cfg.name = "core1";
	ret = ocf_uuid_set_str(&core_cfg.uuid, "core");
	if (ret)
		return ret;

	/* Add core to cache */
	return ocf_mngt_cache_add_core(cache, core, &core_cfg);
}

/*
 * Callback function called when write completes.
 */
void complete_write(struct ocf_io *io, int error)
{
	struct dobj_data *data = ocf_io_get_data(io);

	printf("WRITE COMPLETE: (error: %d)\n", error);

	/* Free data buffer and io */
	ctx_data_free(data);
	ocf_io_put(io);
}

/*
 * Callback function called when read completes.
 */
void complete_read(struct ocf_io *io, int error)
{
	struct dobj_data *data = ocf_io_get_data(io);

	printf("WRITE COMPLETE (error: %d)\n", error);
	printf("DATA: \"%s\"\n", (char *)data->ptr);

	/* Free data buffer and io */
	ctx_data_free(data);
	ocf_io_put(io);
}

/*
 * Wrapper function for io submition.
 */
int submit_io(ocf_core_t core, struct dobj_data *data,
		uint64_t addr, uint64_t len, int dir, ocf_end_io_t cmpl)
{
	struct ocf_io *io;

	/* Allocate new io */
	io = ocf_core_new_io(core);
	if (!io)
		return -ENOMEM;

	/* Setup io address, lenght, direction, flags and ioclass */
	ocf_io_configure(io, addr, len, dir, 0, 0);
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
	struct dobj_data *data1, *data2;

	/* Allocate data buffer and fill it with example data */
	data1 = ctx_data_alloc(1);
	if (!data1)
		error("Unable to allocate data1\n");
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
	if (!data2)
		error("Unable to allocate data2\n");
	/* Prepare and submit read IO to the core */
	submit_io(core, data2, 0, 512, OCF_READ, complete_read);
	/* After read completes, complete_read() callback will be called,
	 * where we print our example data to stdout.
	 */
}

int main(int argc, char *argv[])
{
	ocf_ctx_t ctx;
	ocf_cache_t cache1;
	ocf_core_t core1;

	/* Initialize OCF context */
	if (ctx_init(&ctx))
		error("Unable to initialize context\n");

	/* Start cache */
	if (initialize_cache(ctx, &cache1))
		error("Unable to start cache\n");

	/* Add core */
	if (initialize_core(cache1, &core1))
		error("Unable to add core\n");

	/* Do some actual io operations */
	perform_workload(core1);

	/* Remove core from cache */
	if (ocf_mngt_cache_remove_core(core1))
		error("Unable to remove core\n");

	/* Stop cache */
	if (ocf_mngt_cache_stop(cache1))
		error("Unable to stop cache\n");

	/* Deinitialize context */
	ctx_cleanup(ctx);

	return 0;
}
