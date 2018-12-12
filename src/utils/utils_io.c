/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_priv.h"
#include "../ocf_cache_priv.h"
#include "../ocf_data_obj_priv.h"
#include "../ocf_request.h"
#include "utils_io.h"
#include "utils_cache_line.h"

struct ocf_submit_io_wait_context {
	env_completion complete;
	int error;
	env_atomic rq_remaining;
};

/*
 * IO discard context
 */
struct discard_io_request {
	void *context;
	env_atomic req_remaining;
	env_completion completion;
	int error;
};

static void _ocf_obj_flush_end(struct ocf_io *io, int err)
{
	struct ocf_submit_io_wait_context *cntx = io->priv1;
	cntx->error = err;
	env_completion_complete(&cntx->complete);
}

int ocf_submit_obj_flush_wait(ocf_data_obj_t obj)
{
	struct ocf_submit_io_wait_context cntx = { };
	struct ocf_io *io;

	env_atomic_set(&cntx.rq_remaining, 1);
	env_completion_init(&cntx.complete);

	io = ocf_dobj_new_io(obj);
	if (!io)
		return -ENOMEM;

	ocf_io_configure(io, 0, 0, OCF_WRITE, 0, 0);
	ocf_io_set_cmpl(io, &cntx, NULL, _ocf_obj_flush_end);

	ocf_dobj_submit_flush(io);

	env_completion_wait(&cntx.complete);

	return cntx.error;

}

static void ocf_submit_obj_discard_wait_io(struct ocf_io *io, int error)
{
	struct ocf_submit_io_wait_context *cntx = io->priv1;

	if (error)
		cntx->error = error;

	ocf_io_put(io); /* Release IO */

	if (env_atomic_dec_return(&cntx->rq_remaining))
		return;

	/* All discard IO handled, signal it by setting completion */
	env_completion_complete(&cntx->complete);
}

int ocf_submit_obj_discard_wait(ocf_data_obj_t obj, uint64_t addr,
		uint64_t length)
{
	struct ocf_submit_io_wait_context cntx = { };
	uint32_t bytes;
	uint32_t max_length = ~0;

	ENV_BUG_ON(env_memset(&cntx, sizeof(cntx), 0));
	env_atomic_set(&cntx.rq_remaining, 1);
	env_completion_init(&cntx.complete);

	while (length) {
		struct ocf_io *io = ocf_dobj_new_io(obj);

		if (!io) {
			cntx.error = -ENOMEM;
			break;
		}

		if (length > max_length)
			bytes = max_length;
		else
			bytes = length;

		env_atomic_inc(&cntx.rq_remaining);

		ocf_io_configure(io, addr, bytes, OCF_WRITE, 0, 0);
		ocf_io_set_cmpl(io, &cntx, NULL,
				ocf_submit_obj_discard_wait_io);
		ocf_dobj_submit_discard(io);

		addr += bytes;
		length -= bytes;
	}

	if (env_atomic_dec_return(&cntx.rq_remaining) == 0)
		env_completion_complete(&cntx.complete);

	env_completion_wait(&cntx.complete);

	return cntx.error;
}

static void ocf_submit_obj_zeroes_wait_io(struct ocf_io *io, int error)
{
	struct ocf_submit_io_wait_context *cntx = io->priv1;

	if (error)
		cntx->error = error;

	env_completion_complete(&cntx->complete);
}

int ocf_submit_write_zeroes_wait(ocf_data_obj_t obj, uint64_t addr,
		uint64_t length)
{
	struct ocf_submit_io_wait_context cntx = { };
	uint32_t bytes;
	uint32_t max_length = ~((uint32_t)PAGE_SIZE - 1);
	uint32_t step = 0;
	struct ocf_io *io;

	io = ocf_dobj_new_io(obj);
	if (!io)
		return -ENOMEM;

	while (length) {
		env_completion_init(&cntx.complete);

		bytes = MIN(length, max_length);

		ocf_io_configure(io, addr, bytes, OCF_WRITE, 0, 0);
		ocf_io_set_cmpl(io, &cntx, NULL,
				ocf_submit_obj_zeroes_wait_io);
		ocf_dobj_submit_write_zeroes(io);

		addr += bytes;
		length -= bytes;

		env_completion_wait(&cntx.complete);
		if (cntx.error)
			break;

		OCF_COND_RESCHED_DEFAULT(step);
	}

	ocf_io_put(io);

	return cntx.error;
}

int ocf_submit_cache_page(struct ocf_cache *cache, uint64_t addr,
		int dir, void *buffer)
{
	ctx_data_t *data;
	struct ocf_io *io;
	int result = 0;

	/* Allocate resources for IO */
	io = ocf_dobj_new_io(&cache->device->obj);
	data = ctx_data_alloc(cache->owner, 1);

	if (!io || !data) {
		result = -ENOMEM;
		goto end;
	}

	if (dir == OCF_WRITE)
		ctx_data_wr_check(cache->owner, data, buffer, PAGE_SIZE);

	result = ocf_io_set_data(io, data, 0);
	if (result)
		goto end;

	ocf_io_configure(io, addr, PAGE_SIZE, dir, 0, 0);

	result = ocf_submit_io_wait(io);
	if (result)
		goto end;

	if (dir == OCF_READ)
		ctx_data_rd_check(cache->owner, buffer, data, PAGE_SIZE);
end:
	if (io)
		ocf_io_put(io);
	ctx_data_free(cache->owner, data);
	return result;
}

static void ocf_submit_obj_req_cmpl(struct ocf_io *io, int error)
{
	struct ocf_request *rq = io->priv1;
	ocf_req_end_t callback = io->priv2;

	callback(rq, error);
}

void ocf_submit_cache_reqs(struct ocf_cache *cache,
		struct ocf_map_info *map_info, struct ocf_request *req, int dir,
		unsigned int reqs, ocf_req_end_t callback)
{
	struct ocf_counters_block *cache_stats;
	uint64_t flags = req->io ? req->io->flags : 0;
	uint32_t class = req->io ? req->io->class : 0;
	uint64_t addr, bytes, total_bytes = 0;
	struct ocf_io *io;
	uint32_t i;
	int err;

	cache_stats = &cache->core_obj[req->core_id].
			counters->cache_blocks;

	if (reqs == 1) {
		io = ocf_new_cache_io(cache);
		if (!io) {
			callback(req, -ENOMEM);
			goto update_stats;
		}

		addr = ocf_metadata_map_lg2phy(cache,
					map_info[0].coll_idx);
		addr *= ocf_line_size(cache);
		addr += cache->device->metadata_offset;
		addr += (req->byte_position % ocf_line_size(cache));
		bytes = req->byte_length;

		ocf_io_configure(io, addr, bytes, dir, class, flags);
		ocf_io_set_cmpl(io, req, callback, ocf_submit_obj_req_cmpl);

		err = ocf_io_set_data(io, req->data, 0);
		if (err) {
			ocf_io_put(io);
			callback(req, err);
			goto update_stats;
		}

		ocf_dobj_submit_io(io);
		total_bytes = req->byte_length;

		goto update_stats;
	}

	/* Issue requests to cache. */
	for (i = 0; i < reqs; i++) {
		io = ocf_new_cache_io(cache);

		if (!io) {
			/* Finish all IOs which left with ERROR */
			for (; i < reqs; i++)
				callback(req, -ENOMEM);
			goto update_stats;
		}

		addr  = ocf_metadata_map_lg2phy(cache,
				map_info[i].coll_idx);
		addr *= ocf_line_size(cache);
		addr += cache->device->metadata_offset;
		bytes = ocf_line_size(cache);

		if (i == 0) {
			uint64_t seek = (req->byte_position %
					ocf_line_size(cache));

			addr += seek;
			bytes -= seek;
		} else  if (i == (reqs - 1)) {
			uint64_t skip = (ocf_line_size(cache) -
				((req->byte_position + req->byte_length) %
				ocf_line_size(cache))) % ocf_line_size(cache);

			bytes -= skip;
		}

		ocf_io_configure(io, addr, bytes, dir, class, flags);
		ocf_io_set_cmpl(io, req, callback, ocf_submit_obj_req_cmpl);

		err = ocf_io_set_data(io, req->data, total_bytes);
		if (err) {
			ocf_io_put(io);
			/* Finish all IOs which left with ERROR */
			for (; i < reqs; i++)
				callback(req, err);
			goto update_stats;
		}
		ocf_dobj_submit_io(io);
		total_bytes += bytes;
	}

update_stats:
	if (dir == OCF_WRITE)
		env_atomic64_add(total_bytes, &cache_stats->write_bytes);
	else if (dir == OCF_READ)
		env_atomic64_add(total_bytes, &cache_stats->read_bytes);
}

void ocf_submit_obj_req(ocf_data_obj_t obj, struct ocf_request *req,
		ocf_req_end_t callback)
{
	struct ocf_cache *cache = req->cache;
	struct ocf_counters_block *core_stats;
	uint64_t flags = req->io ? req->io->flags : 0;
	uint32_t class = req->io ? req->io->class : 0;
	int dir = req->rw;
	struct ocf_io *io;
	int err;

	core_stats = &cache->core_obj[req->core_id].
			counters->core_blocks;
	if (dir == OCF_WRITE)
		env_atomic64_add(req->byte_length, &core_stats->write_bytes);
	else if (dir == OCF_READ)
		env_atomic64_add(req->byte_length, &core_stats->read_bytes);

	io = ocf_dobj_new_io(obj);
	if (!io) {
		callback(req, -ENOMEM);
		return;
	}

	ocf_io_configure(io, req->byte_position, req->byte_length, dir,
			class, flags);
	ocf_io_set_cmpl(io, req, callback, ocf_submit_obj_req_cmpl);
	err = ocf_io_set_data(io, req->data, 0);
	if (err) {
		ocf_io_put(io);
		callback(req, err);
		return;
	}
	ocf_dobj_submit_io(io);
}

static void ocf_submit_io_wait_end(struct ocf_io *io, int error)
{
	struct ocf_submit_io_wait_context *context = io->priv1;

	context->error |= error;
	env_completion_complete(&context->complete);
}

int ocf_submit_io_wait(struct ocf_io *io)
{
	struct ocf_submit_io_wait_context context;

	ENV_BUG_ON(env_memset(&context, sizeof(context), 0));
	env_completion_init(&context.complete);
	context.error = 0;

	ocf_io_set_cmpl(io, &context, NULL, ocf_submit_io_wait_end);
	ocf_dobj_submit_io(io);
	env_completion_wait(&context.complete);
	return context.error;
}
