/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_d2c.h"
#include "engine_common.h"
#include "cache_engine.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_io.h"
#include "../metadata/metadata.h"

#define OCF_ENGINE_DEBUG_IO_NAME "d2c"
#include "engine_debug.h"

static void _ocf_d2c_completion(void *private_data, int error)
{
	struct ocf_request *rq = private_data;

	rq->error = error;

	OCF_DEBUG_RQ(rq, "Completion");

	if (rq->error) {
		rq->info.core_error = 1;
		if (rq->rw == OCF_READ) {
			env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				core_errors.read);
		} else {
			env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				core_errors.write);
		}
	}

	/* Complete request */
	rq->complete(rq, rq->error);

	/* Release OCF request */
	ocf_rq_put(rq);
}

int ocf_io_d2c(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	OCF_DEBUG_TRACE(rq->cache);

	ocf_io_start(rq->io);

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	ocf_submit_obj_req(&cache->core_obj[rq->core_id].obj, rq, rq->rw,
			_ocf_d2c_completion, rq);

	ocf_engine_update_block_stats(rq);

	if (rq->rw == OCF_READ) {
		env_atomic64_inc(&cache->core_obj[rq->core_id].counters->
			part_counters[rq->part_id].read_reqs.pass_through);
	} else {
		env_atomic64_inc(&cache->core_obj[rq->core_id].counters->
			part_counters[rq->part_id].write_reqs.pass_through);
	}

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;

}
