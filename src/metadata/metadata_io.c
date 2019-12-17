/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "metadata.h"
#include "metadata_io.h"
#include "../ocf_priv.h"
#include "../engine/cache_engine.h"
#include "../engine/engine_common.h"
#include "../engine/engine_bf.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_realloc.h"
#include "../utils/utils_io.h"
#include "../ocf_request.h"
#include "../ocf_def_priv.h"

#define OCF_METADATA_IO_DEBUG 0

#if 1 == OCF_METADATA_IO_DEBUG
#define OCF_DEBUG_TRACE(cache) \
	ocf_cache_log(cache, log_info, "[Metadata][IO] %s\n", __func__)

#define OCF_DEBUG_MSG(cache, msg) \
	ocf_cache_log(cache, log_info, "[Metadata][IO] %s - %s\n", \
			__func__, msg)

#define OCF_DEBUG_PARAM(cache, format, ...) \
	ocf_cache_log(cache, log_info, "[Metadata][IO] %s - "format"\n", \
			__func__, ##__VA_ARGS__)
#else
#define OCF_DEBUG_TRACE(cache)
#define OCF_DEBUG_MSG(cache, msg)
#define OCF_DEBUG_PARAM(cache, format, ...)
#endif

struct metadata_io_read_i_atomic_context {
	struct ocf_request *req;
	ctx_data_t *data;
	ocf_cache_t cache;
	uint64_t count;
	uint64_t curr_offset;
	uint64_t curr_count;

	ocf_metadata_atomic_io_event_t drain_hndl;
	ocf_metadata_io_end_t compl_hndl;
	void *priv;
};

static void metadata_io_read_i_atomic_complete(
		struct metadata_io_read_i_atomic_context *context, int error)
{
	context->compl_hndl(context->cache, context->priv, error);

	ctx_data_free(context->cache->owner, context->data);
	ocf_req_put(context->req);
	env_vfree(context);
}

/*
 * Iterative read end callback
 */
static void metadata_io_read_i_atomic_step_end(struct ocf_io *io, int error)
{
	struct metadata_io_read_i_atomic_context *context = io->priv1;

	OCF_DEBUG_TRACE(ocf_volume_get_cache(ocf_io_get_volume(io)));

	ocf_io_put(io);

	if (error) {
		metadata_io_read_i_atomic_complete(context, error);
		return;
	}

	context->drain_hndl(context->priv, context->curr_offset,
			context->curr_count, context->data);

	context->count -= context->curr_count;
	context->curr_offset += context->curr_count;

	if (context->count > 0)
		ocf_engine_push_req_front(context->req, true);
	else
		metadata_io_read_i_atomic_complete(context, 0);
}

int metadata_io_read_i_atomic_step(struct ocf_request *req)
{
	struct metadata_io_read_i_atomic_context *context = req->priv;
	ocf_cache_t cache = context->cache;
	uint64_t max_sectors_count = PAGE_SIZE / OCF_ATOMIC_METADATA_SIZE;
	struct ocf_io *io;
	int result = 0;

	/* Get sectors count of this IO iteration */
	context->curr_count = OCF_MIN(max_sectors_count, context->count);

	/* Reset position in data buffer */
	ctx_data_seek(cache->owner, context->data, ctx_data_seek_begin, 0);

	/* Allocate new IO */
	io = ocf_new_cache_io(cache, req->io_queue,
			cache->device->metadata_offset +
			SECTORS_TO_BYTES(context->curr_offset),
			SECTORS_TO_BYTES(context->curr_count), OCF_READ, 0, 0);

	if (!io) {
		metadata_io_read_i_atomic_complete(context, -OCF_ERR_NO_MEM);
		return 0;
	}

	/* Setup IO */
	ocf_io_set_cmpl(io, context, NULL, metadata_io_read_i_atomic_step_end);
	result = ocf_io_set_data(io, context->data, 0);
	if (result) {
		ocf_io_put(io);
		metadata_io_read_i_atomic_complete(context, result);
		return 0;
	}

	/* Submit IO */
	ocf_volume_submit_metadata(io);

	return 0;
}

static const struct ocf_io_if _io_if_metadata_io_read_i_atomic_step = {
	.read = metadata_io_read_i_atomic_step,
	.write = metadata_io_read_i_atomic_step,
};

/*
 * Iterative read request
 */
int metadata_io_read_i_atomic(ocf_cache_t cache, ocf_queue_t queue, void *priv,
		ocf_metadata_atomic_io_event_t drain_hndl,
		ocf_metadata_io_end_t compl_hndl)
{
	struct metadata_io_read_i_atomic_context *context;
	uint64_t io_sectors_count = cache->device->collision_table_entries *
					ocf_line_sectors(cache);

	OCF_DEBUG_TRACE(cache);

	context = env_vzalloc(sizeof(*context));
	if (!context)
		return -OCF_ERR_NO_MEM;

	context->req = ocf_req_new(queue, NULL, 0, 0, 0);
	if (!context->req) {
		env_vfree(context);
		return -OCF_ERR_NO_MEM;
	}

	context->req->info.internal = true;
	context->req->io_if = &_io_if_metadata_io_read_i_atomic_step;
	context->req->priv = context;

	/* Allocate one 4k page for metadata*/
	context->data = ctx_data_alloc(cache->owner, 1);
	if (!context->data) {
		ocf_req_put(context->req);
		env_vfree(context);
		return -OCF_ERR_NO_MEM;
	}

	context->cache = cache;
	context->count = io_sectors_count;
	context->curr_offset = 0;
	context->curr_count = 0;
	context->drain_hndl = drain_hndl;
	context->compl_hndl = compl_hndl;
	context->priv = priv;

	ocf_engine_push_req_front(context->req, true);

	return 0;
}

static void metadata_io_i_asynch_end(struct metadata_io_request *request,
		int error);

static int ocf_restart_meta_io(struct ocf_request *req);

static struct ocf_io_if meta_restart_if = {
		.read = ocf_restart_meta_io,
		.write = ocf_restart_meta_io
};

static void metadata_io_i_asynch_cmpl(struct ocf_io *io, int error)
{
	struct metadata_io_request *request = io->priv1;

	metadata_io_i_asynch_end(request, error);

	ocf_io_put(io);
}

static void metadata_io_req_fill(struct metadata_io_request *meta_io_req)
{
	ocf_cache_t cache = meta_io_req->cache;
	int i;

	for (i = 0; i < meta_io_req->count; i++) {
		meta_io_req->on_meta_fill(cache, meta_io_req->data,
			meta_io_req->page + i, meta_io_req->context);
	}
}

static void metadata_io_req_drain(struct metadata_io_request *meta_io_req)
{
	ocf_cache_t cache = meta_io_req->cache;
	int i;

	for (i = 0; i < meta_io_req->count; i++) {
		meta_io_req->on_meta_drain(cache, meta_io_req->data,
			meta_io_req->page + i, meta_io_req->context);
	}
}

static int ocf_restart_meta_io(struct ocf_request *req)
{
	struct metadata_io_request *meta_io_req = req->priv;
	ocf_cache_t cache = req->cache;
	struct ocf_io *io;
	int ret;

	/* Fill with the latest metadata. */
	ocf_metadata_start_shared_access(&cache->metadata.lock);
	metadata_io_req_fill(meta_io_req);
	ocf_metadata_end_shared_access(&cache->metadata.lock);

	io = ocf_new_cache_io(cache, req->io_queue,
			PAGES_TO_BYTES(meta_io_req->page),
			PAGES_TO_BYTES(meta_io_req->count),
			OCF_WRITE, 0, 0);
	if (!io) {
		metadata_io_i_asynch_end(meta_io_req, -OCF_ERR_NO_MEM);
		return 0;
	}

	/* Setup IO */
	ocf_io_set_cmpl(io, meta_io_req, NULL, metadata_io_i_asynch_cmpl);
	ret = ocf_io_set_data(io, meta_io_req->data, 0);
	if (ret) {
		ocf_io_put(io);
		metadata_io_i_asynch_end(meta_io_req, ret);
		return ret;
	}
	ocf_volume_submit_io(io);
	return 0;
}

/*
 * Iterative asynchronous write callback
 */
static void metadata_io_i_asynch_end(struct metadata_io_request *request,
		int error)
{
	struct metadata_io_request_asynch *a_req;
	ocf_cache_t cache;

	OCF_CHECK_NULL(request);

	cache = request->cache;

	a_req = request->asynch;
	OCF_CHECK_NULL(a_req);
	OCF_CHECK_NULL(a_req->on_complete);

	if (error) {
		request->error |= error;
		request->asynch->error |= error;
	} else {
		if (request->fl_req.rw == OCF_READ)
			metadata_io_req_drain(request);
	}

	if (env_atomic_dec_return(&request->req_remaining))
		return;

	OCF_DEBUG_PARAM(cache, "Page = %u", request->page);

	ctx_data_free(cache->owner, request->data);
	request->data = NULL;

	if (env_atomic_dec_return(&a_req->req_remaining)) {
		env_atomic_set(&request->finished, 1);
		ocf_metadata_updater_kick(cache);
		return;
	}

	OCF_DEBUG_MSG(cache, "Asynchronous IO completed");

	/* All IOs have been finished, call IO end callback */
	a_req->on_complete(request->cache, a_req->context, request->error);

	/*
	 * If it's last request, we mark is as finished
	 * after calling IO end callback
	 */
	env_atomic_set(&request->finished, 1);
	ocf_metadata_updater_kick(cache);
}

static uint32_t metadata_io_max_page(ocf_cache_t cache)
{
	return ocf_volume_get_max_io_size(&cache->device->volume) / PAGE_SIZE;
}

static void metadata_io_req_error(ocf_cache_t cache,
				  struct metadata_io_request_asynch *a_req,
				  uint32_t i, int error)
{
	a_req->error |= error;
	a_req->reqs[i].error |= error;
	a_req->reqs[i].count = 0;
	if (a_req->reqs[i].data)
		ctx_data_free(cache->owner, a_req->reqs[i].data);
	a_req->reqs[i].data = NULL;
}

/*
 * Iterative write request asynchronously
 */
static int metadata_io_i_asynch(ocf_cache_t cache, ocf_queue_t queue, int dir,
		void *context, uint32_t page, uint32_t count,
		ocf_metadata_io_event_t io_hndl,
		ocf_metadata_io_end_t compl_hndl)
{
	uint32_t curr_count, written;
	uint32_t max_count = metadata_io_max_page(cache);
	uint32_t io_count = OCF_DIV_ROUND_UP(count, max_count);
	uint32_t i;
	int error = 0, ret;
	struct ocf_io *io;

	/* Allocation and initialization of asynchronous metadata IO request */
	struct metadata_io_request_asynch *a_req;

	if (count == 0)
		return 0;

	a_req = env_zalloc(sizeof(*a_req), ENV_MEM_NOIO);
	if (!a_req)
		return -OCF_ERR_NO_MEM;

	env_atomic_set(&a_req->req_remaining, io_count);
	env_atomic_set(&a_req->req_active, io_count);
	a_req->on_complete = compl_hndl;
	a_req->context = context;
	a_req->page = page;

	/* Allocate particular requests and initialize them  */
	OCF_REALLOC_CP(&a_req->reqs, sizeof(a_req->reqs[0]),
			io_count, &a_req->reqs_limit);
	if (!a_req->reqs) {
		env_free(a_req);
		ocf_cache_log(cache, log_warn,
				"No memory during metadata IO\n");
		return -OCF_ERR_NO_MEM;
	}
	/* IO Requests initialization */
	for (i = 0; i < io_count; i++) {
		env_atomic_set(&(a_req->reqs[i].req_remaining), 1);
		env_atomic_set(&(a_req->reqs[i].finished), 0);
		a_req->reqs[i].asynch = a_req;
	}

	OCF_DEBUG_PARAM(cache, "IO count = %u", io_count);

	i = 0;
	written = 0;
	while (count) {
		/* Get pages count of this IO iteration */
		if (count > max_count)
			curr_count = max_count;
		else
			curr_count = count;

		/* Fill request */
		a_req->reqs[i].cache = cache;
		a_req->reqs[i].context = context;
		a_req->reqs[i].page = page + written;
		a_req->reqs[i].count = curr_count;
		a_req->reqs[i].on_meta_fill = io_hndl;
		a_req->reqs[i].on_meta_drain = io_hndl;
		a_req->reqs[i].fl_req.io_if = &meta_restart_if;
		a_req->reqs[i].fl_req.io_queue = queue;
		a_req->reqs[i].fl_req.cache = cache;
		a_req->reqs[i].fl_req.priv = &a_req->reqs[i];
		a_req->reqs[i].fl_req.info.internal = true;
		a_req->reqs[i].fl_req.rw = dir;

		/*
		 * We don't want allocate map for this request in
		 * threads.
		 */
		a_req->reqs[i].fl_req.map = LIST_POISON1;

		INIT_LIST_HEAD(&a_req->reqs[i].list);

		a_req->reqs[i].data = ctx_data_alloc(cache->owner, curr_count);
		if (!a_req->reqs[i].data) {
			error = -OCF_ERR_NO_MEM;
			metadata_io_req_error(cache, a_req, i, error);
			break;
		}

		/* Issue IO if it is not overlapping with anything else */
		ret = metadata_updater_check_overlaps(cache, &a_req->reqs[i]);
		if (ret == 0) {
			/* Allocate new IO */
			io = ocf_new_cache_io(cache, queue,
					PAGES_TO_BYTES(a_req->reqs[i].page),
					PAGES_TO_BYTES(a_req->reqs[i].count),
					dir, 0, 0);
			if (!io) {
				error = -OCF_ERR_NO_MEM;
				metadata_io_req_error(cache, a_req, i, error);
				break;
			}

			if (dir == OCF_WRITE)
				metadata_io_req_fill(&a_req->reqs[i]);

			/* Setup IO */
			ocf_io_set_cmpl(io, &a_req->reqs[i], NULL,
					metadata_io_i_asynch_cmpl);
			error = ocf_io_set_data(io, a_req->reqs[i].data, 0);
			if (error) {
				ocf_io_put(io);
				metadata_io_req_error(cache, a_req, i, error);
				break;
			}

			ocf_volume_submit_io(io);
		}

		count -= curr_count;
		written += curr_count;
		i++;
	}

	if (error == 0) {
		/* No error, return 0 that indicates operation successful */
		return 0;
	}

	OCF_DEBUG_MSG(cache, "ERROR");

	if (i == 0) {
		/*
		 * If no requests were submitted, we just call completion
		 * callback, free memory and return error.
		 */
		compl_hndl(cache, context, error);

		OCF_REALLOC_DEINIT(&a_req->reqs, &a_req->reqs_limit);
		env_free(a_req);

		return error;
	}

	/*
	 * Decrement total reaming requests with IO that were not triggered.
	 * If we reached zero, we need to call completion callback.
	 */
	if (env_atomic_sub_return(io_count - i, &a_req->req_remaining) == 0)
		compl_hndl(cache, context, error);

	/*
	 * Decrement total active requests with IO that were not triggered.
	 * If we reached zero, we need to free memory.
	 */
	if (env_atomic_sub_return(io_count - i, &a_req->req_active) == 0) {
		OCF_REALLOC_DEINIT(&a_req->reqs, &a_req->reqs_limit);
		env_free(a_req);
	}

	return error;
}

int metadata_io_write_i_asynch(ocf_cache_t cache, ocf_queue_t queue,
		void *context, uint32_t page, uint32_t count,
		ocf_metadata_io_event_t fill_hndl,
		ocf_metadata_io_end_t compl_hndl)
{
	return metadata_io_i_asynch(cache, queue, OCF_WRITE, context,
			page, count, fill_hndl, compl_hndl);
}

int metadata_io_read_i_asynch(ocf_cache_t cache, ocf_queue_t queue,
		void *context, uint32_t page, uint32_t count,
		ocf_metadata_io_event_t drain_hndl,
		ocf_metadata_io_end_t compl_hndl)
{
	return metadata_io_i_asynch(cache, queue, OCF_READ, context,
			page, count, drain_hndl, compl_hndl);
}

int ocf_metadata_io_init(ocf_cache_t cache)
{
	return ocf_metadata_updater_init(cache);
}

void ocf_metadata_io_deinit(ocf_cache_t cache)
{
	ocf_metadata_updater_stop(cache);
}
