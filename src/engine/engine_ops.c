/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_common.h"
#include "cache_engine.h"
#include "engine_ops.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_io.h"

#define OCF_ENGINE_DEBUG_IO_NAME "ops"
#include "engine_debug.h"

static void _ocf_engine_ops_io(void *private_data, int error)
{
	struct ocf_request *rq = private_data;

	if (error)
		rq->error |= error;

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	OCF_DEBUG_RQ(rq, "Completion");

	if (rq->error) {
		/* An error occured */
		ocf_engine_error(rq, false, "Core operation failure");
	}

	/* Complete requests - both to cache and to core*/
	rq->complete(rq, rq->error);

	/* Release OCF request */
	ocf_rq_put(rq);
}

int ocf_engine_ops(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	OCF_DEBUG_TRACE(rq->cache);

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	/* IO to the core device and to the cache device */
	env_atomic_set(&rq->req_remaining, 2);

	/* Submit operation into core device */
	ocf_submit_obj_req(&cache->core_obj[rq->core_id].obj, rq, rq->rw,
			_ocf_engine_ops_io, rq);

	ocf_submit_cache_reqs(cache, rq->map, rq, rq->rw,
			1, _ocf_engine_ops_io, rq);

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}


