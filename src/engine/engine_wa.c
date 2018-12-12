/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_wa.h"
#include "engine_common.h"
#include "cache_engine.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_io.h"
#include "../metadata/metadata.h"

#define OCF_ENGINE_DEBUG_IO_NAME "wa"
#include "engine_debug.h"

static void _ocf_read_wa_io(struct ocf_request *rq, int error)
{
	if (error)
		rq->error |= error;

	if (env_atomic_dec_return(&rq->req_remaining))
		return;

	if (rq->error) {
		rq->info.core_error = 1;
		env_atomic_inc(&rq->cache->core_obj[rq->core_id].counters->
				core_errors.write);
	}

	/* Complete request */
	rq->complete(rq, rq->error);

	OCF_DEBUG_RQ(rq, "Completion");

	/* Release OCF request */
	ocf_rq_put(rq);
}

int ocf_write_wa(struct ocf_request *rq)
{
	struct ocf_cache *cache = rq->cache;

	ocf_io_start(rq->io);

	/* Get OCF request - increase reference counter */
	ocf_rq_get(rq);

	OCF_METADATA_LOCK_RD(); /*- Metadata RD access -----------------------*/

	/* Traverse request to check if there are mapped cache lines */
	ocf_engine_traverse(rq);

	OCF_METADATA_UNLOCK_RD(); /*- END Metadata RD access -----------------*/

	if (ocf_engine_is_hit(rq)) {
		ocf_rq_clear(rq);

		/* There is HIT, do WT */
		ocf_get_io_if(ocf_cache_mode_wt)->write(rq);

	} else if (ocf_engine_mapped_count(rq)) {
		ocf_rq_clear(rq);

		/* Partial MISS, do WI */
		ocf_get_io_if(ocf_cache_mode_wi)->write(rq);
	} else {

		/* There is no mapped cache line, write directly into core */

		OCF_DEBUG_RQ(rq, "Submit");

		/* Submit write IO to the core */
		env_atomic_set(&rq->req_remaining, 1);
		ocf_submit_obj_req(&cache->core_obj[rq->core_id].obj, rq,
				_ocf_read_wa_io);

		/* Update statistics */
		ocf_engine_update_block_stats(rq);
		env_atomic64_inc(&cache->core_obj[rq->core_id].counters->
			part_counters[rq->part_id].write_reqs.pass_through);
	}

	/* Put OCF request - decrease reference counter */
	ocf_rq_put(rq);

	return 0;
}


