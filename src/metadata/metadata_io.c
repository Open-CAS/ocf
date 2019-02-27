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
#include "../utils/utils_allocator.h"
#include "../utils/utils_io.h"
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

static void metadata_io_write_i_asynch_end(struct metadata_io_request *request,
		int error);
static int ocf_restart_meta_io(struct ocf_request *req);

static struct ocf_io_if meta_restart_if = {
		.read = ocf_restart_meta_io,
		.write = ocf_restart_meta_io
};

/*
 * Get max pages for IO
 */
static uint32_t metadata_io_max_page(ocf_cache_t cache)
{
	return ocf_volume_get_max_io_size(&cache->device->volume) / PAGE_SIZE;
}

/*
 * Iterative read end callback
 */
static void metadata_io_read_i_atomic_end(struct ocf_io *io, int error)
{
	struct metadata_io_request_atomic *meta_atom_req = io->priv1;

	OCF_DEBUG_TRACE(ocf_volume_get_cache(io->volume));

	meta_atom_req->error |= error;
	env_completion_complete(&meta_atom_req->complete);
}

/*
 * Iterative read request
 */
int metadata_io_read_i_atomic(ocf_cache_t cache,
		ocf_metadata_atomic_io_event_t hndl)
{
	uint64_t i;
	uint64_t max_sectors_count = PAGE_SIZE / OCF_ATOMIC_METADATA_SIZE;
	uint64_t io_sectors_count = cache->device->collision_table_entries *
					ocf_line_sectors(cache);
	uint64_t count, curr_count;
	int result = 0;
	struct ocf_io *io;
	ctx_data_t *data;
	struct metadata_io_request_atomic meta_atom_req;
	unsigned char step = 0;

	OCF_DEBUG_TRACE(cache);

	/* Allocate one 4k page for metadata*/
	data = ctx_data_alloc(cache->owner, 1);
	if (!data)
		return -ENOMEM;

	count = io_sectors_count;
	for (i = 0; i < io_sectors_count; i += curr_count) {
		/* Get sectors count of this IO iteration */
		curr_count = OCF_MIN(max_sectors_count, count);

		env_completion_init(&meta_atom_req.complete);
		meta_atom_req.error = 0;

		/* Reset position in data buffer */
		ctx_data_seek(cache->owner, data, ctx_data_seek_begin, 0);

		/* Allocate new IO */
		io = ocf_new_cache_io(cache);
		if (!io) {
			result = -ENOMEM;
			break;
		}

		/* Setup IO */
		ocf_io_configure(io,
				cache->device->metadata_offset +
					SECTORS_TO_BYTES(i),
				SECTORS_TO_BYTES(curr_count),
				OCF_READ, 0, 0);
		ocf_io_set_cmpl(io, &meta_atom_req, NULL,
				metadata_io_read_i_atomic_end);
		result = ocf_io_set_data(io, data, 0);
		if (result) {
			ocf_io_put(io);
			break;
		}

		/* Submit IO */
		ocf_volume_submit_metadata(io);
		ocf_io_put(io);

		/* Wait for completion of IO */
		env_completion_wait(&meta_atom_req.complete);

		/* Check for error */
		if (meta_atom_req.error) {
			result = meta_atom_req.error;
			break;
		}

		result |= hndl(cache, i, curr_count, data);
		if (result)
			break;

		count -= curr_count;

		OCF_COND_RESCHED(step, 128);
	}

	/* Memory free */
	ctx_data_free(cache->owner, data);

	return result;
}

static void metadata_io_write_i_asynch_cmpl(struct ocf_io *io, int error)
{
	struct metadata_io_request *request = io->priv1;

	metadata_io_write_i_asynch_end(request, error);

	ocf_io_put(io);
}

static int ocf_restart_meta_io(struct ocf_request *req)
{
	struct ocf_io *io;
	struct metadata_io_request *meta_io_req;
	ocf_cache_t cache;
	int i;
	int ret;

	cache = req->cache;
	meta_io_req = req->priv;

	/* Fill with the latest metadata. */
	OCF_METADATA_LOCK_RD();
	for (i = 0; i < meta_io_req->count; i++) {
		meta_io_req->on_meta_fill(cache, meta_io_req->data,
			meta_io_req->page + i, meta_io_req->context);

	}
	OCF_METADATA_UNLOCK_RD();

	io = ocf_new_cache_io(cache);
	if (!io) {
		metadata_io_write_i_asynch_end(meta_io_req, -ENOMEM);
		return 0;
	}

	/* Setup IO */
	ocf_io_configure(io,
			PAGES_TO_BYTES(meta_io_req->page),
			PAGES_TO_BYTES(meta_io_req->count),
			OCF_WRITE, 0, 0);

	ocf_io_set_cmpl(io, meta_io_req, NULL, metadata_io_write_i_asynch_cmpl);
	ret = ocf_io_set_data(io, meta_io_req->data, 0);
	if (ret) {
		ocf_io_put(io);
		metadata_io_write_i_asynch_end(meta_io_req, ret);
		return ret;
	}
	ocf_volume_submit_io(io);
	return 0;
}

/*
 * Iterative asynchronous write callback
 */
static void metadata_io_write_i_asynch_end(struct metadata_io_request *request,
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
int metadata_io_write_i_asynch(ocf_cache_t cache, ocf_queue_t queue,
		void *context, uint32_t page, uint32_t count,
		ocf_metadata_io_event_t fill_hndl,
		ocf_metadata_io_hndl_on_write_t compl_hndl)
{
	uint32_t curr_count, written;
	uint32_t max_count = metadata_io_max_page(cache);
	uint32_t io_count = OCF_DIV_ROUND_UP(count, max_count);
	uint32_t i, i_fill;
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
		a_req->reqs[i].on_meta_fill = fill_hndl;
		a_req->reqs[i].fl_req.io_if = &meta_restart_if;
		a_req->reqs[i].fl_req.io_queue = queue;
		a_req->reqs[i].fl_req.cache = cache;
		a_req->reqs[i].fl_req.priv = &a_req->reqs[i];
		a_req->reqs[i].fl_req.info.internal = true;

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
			io = ocf_new_cache_io(cache);
			if (!io) {
				error = -OCF_ERR_NO_MEM;
				metadata_io_req_error(cache, a_req, i, error);
				break;
			}

			for (i_fill = 0; i_fill < curr_count; i_fill++) {
				fill_hndl(cache, a_req->reqs[i].data,
						page + written + i_fill,
						context);
			}

			/* Setup IO */
			ocf_io_configure(io,
					PAGES_TO_BYTES(a_req->reqs[i].page),
					PAGES_TO_BYTES(a_req->reqs[i].count),
					OCF_WRITE, 0, 0);

			ocf_io_set_cmpl(io, &a_req->reqs[i], NULL,
					metadata_io_write_i_asynch_cmpl);
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

int ocf_metadata_io_init(ocf_cache_t cache)
{
	return ocf_metadata_updater_init(cache);
}

void ocf_metadata_io_deinit(ocf_cache_t cache)
{
	ocf_metadata_updater_stop(cache);
}

static void metadata_io_end(struct ocf_io *io, int error)
{
	struct metadata_io *mio = io->priv1;
	ctx_data_t *data = ocf_io_get_data(io);
	uint32_t page = BYTES_TO_PAGES(io->addr);
	uint32_t count = BYTES_TO_PAGES(io->bytes);
	ocf_cache_t cache = mio->cache;
	uint32_t i = 0;

	if (error) {
		mio->error |= error;
		goto out;
	}

	for (i = 0; mio->dir == OCF_READ && i < count; i++) {
		mio->error |= mio->hndl_fn(cache, data, page + i,
				mio->hndl_cntx);
	}

out:
	ctx_data_free(cache->owner, data);
	ocf_io_put(io);

	if (env_atomic_dec_return(&mio->req_remaining))
		return;

	env_completion_complete(&mio->completion);
}

static int metadata_submit_io(
		ocf_cache_t cache,
		struct metadata_io *mio,
		uint32_t count,
		uint32_t written)
{
	ctx_data_t *data;
	struct ocf_io *io;
	int err;
	int i;

	/* Allocate IO */
	io = ocf_new_cache_io(cache);
	if (!io) {
		err = -ENOMEM;
		goto error;
	}

	/* Allocate data buffer for this IO */
	data = ctx_data_alloc(cache->owner, count);
	if (!data) {
		err = -ENOMEM;
		goto put_io;
	}

	/* Fill data */
	for (i = 0; mio->dir == OCF_WRITE && i < count; i++) {
		err = mio->hndl_fn(cache, data,
				mio->page + written + i, mio->hndl_cntx);
		if (err)
			goto free_data;
	}

	/* Setup IO */
	ocf_io_configure(io,
			PAGES_TO_BYTES(mio->page + written),
			PAGES_TO_BYTES(count),
			mio->dir, 0, 0);
	ocf_io_set_cmpl(io, mio, NULL, metadata_io_end);
	err = ocf_io_set_data(io, data, 0);
	if (err)
		goto free_data;

	/* Submit IO */
	env_atomic_inc(&mio->req_remaining);
	ocf_volume_submit_io(io);

	return 0;

free_data:
	ctx_data_free(cache->owner, data);
put_io:
	ocf_io_put(io);
error:
	mio->error = err;
	return err;
}


/*
 *
 */
static int metadata_io(struct metadata_io *mio)
{
	uint32_t max_count = metadata_io_max_page(mio->cache);
	uint32_t this_count, written = 0;
	uint32_t count = mio->count;
	unsigned char step = 0;
	int err;

	ocf_cache_t cache = mio->cache;

	/* Check direction value correctness */
	switch (mio->dir) {
	case OCF_WRITE:
	case OCF_READ:
		break;
	default:
		return -EINVAL;
	}

	env_atomic_set(&mio->req_remaining, 1);
	env_completion_init(&mio->completion);

	while (count) {
		this_count = OCF_MIN(count, max_count);

		err = metadata_submit_io(cache, mio, this_count, written);
		if (err)
			break;

		/* Update counters */
		count -= this_count;
		written += this_count;

		OCF_COND_RESCHED(step, 128);
	}

	if (env_atomic_dec_return(&mio->req_remaining) == 0)
		env_completion_complete(&mio->completion);

	/* Wait for all IO to be finished */
	env_completion_wait(&mio->completion);

	return mio->error;
}

/*
 *
 */
int metadata_io_write_i(ocf_cache_t cache,
		uint32_t page, uint32_t count,
		ocf_metadata_io_event_t hndl_fn, void *hndl_cntx)
{
	struct metadata_io mio = {
		.dir = OCF_WRITE,
		.cache = cache,
		.page = page,
		.count = count,
		.hndl_fn = hndl_fn,
		.hndl_cntx = hndl_cntx,
	};

	return metadata_io(&mio);
}

/*
 *
 */
int metadata_io_read_i(ocf_cache_t cache,
		uint32_t page, uint32_t count,
		ocf_metadata_io_event_t hndl_fn, void *hndl_cntx)
{
	struct metadata_io mio = {
		.dir = OCF_READ,
		.cache = cache,
		.page = page,
		.count = count,
		.hndl_fn = hndl_fn,
		.hndl_cntx = hndl_cntx,
	};

	return metadata_io(&mio);
}

/*
 *
 */
static int metadata_io_write_fill(ocf_cache_t cache,
		ctx_data_t *data, uint32_t page, void *context)
{
	ctx_data_wr_check(cache->owner, data, context, PAGE_SIZE);
	return 0;
}

/*
 * Write request
 */
int metadata_io_write(ocf_cache_t cache,
		void *data, uint32_t page)
{
	struct metadata_io mio = {
		.dir = OCF_WRITE,
		.cache = cache,
		.page = page,
		.count = 1,
		.hndl_fn = metadata_io_write_fill,
		.hndl_cntx = data,
	};


	return metadata_io(&mio);
}
