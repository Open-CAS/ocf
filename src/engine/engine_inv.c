/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_inv.h"
#include "engine_common.h"
#include "cache_engine.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_cache_line.h"
#include "../metadata/metadata.h"
#include "../concurrency/ocf_concurrency.h"

#define OCF_ENGINE_DEBUG_IO_NAME "inv"
#include "engine_debug.h"

static void _ocf_invalidate_rq(void *private_data, int error)
{
	struct ocf_request *rq = private_data;

	if (error) {
		rq->error = error;
		env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				cache_errors.write);
	}

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	OCF_DEBUG_RQ(rq, "Completion");

	if (rq->error)
		ocf_engine_error(rq, true, "Failed to flush metadata to cache");

	ocf_rq_unlock(rq);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);
}

static int _ocf_invalidate_do(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	ENV_BUG_ON(env_atomic_read(&rq->req_remaining));

	OCF_METADATA_LOCK_WR();
	ocf_purge_map_info(rq);
	OCF_METADATA_UNLOCK_WR();

	env_atomic_inc(&rq->req_remaining);

	if (ocf_data_obj_is_atomic(&cache->device->obj) &&
			rq->info.flush_metadata) {
		/* Metadata flush IO */
		ocf_metadata_flush_do_asynch(cache, rq, _ocf_invalidate_rq);
	}

	_ocf_invalidate_rq(rq, 0);

	return 0;
}

static const struct ocf_io_if _io_if_invalidate = {
	.read = _ocf_invalidate_do,
	.write = _ocf_invalidate_do,
};

void ocf_engine_invalidate(struct ocf_request *rq)
{
	ocf_engine_push_rq_front_if(rq, &_io_if_invalidate, true);
}
