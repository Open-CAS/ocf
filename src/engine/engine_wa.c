/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "engine_wa.h"
#include "engine_common.h"
#include "cache_engine.h"
#include "../ocf_request.h"
#include "../utils/utils_io.h"
#include "../metadata/metadata.h"

#define OCF_ENGINE_DEBUG_IO_NAME "wa"
#include "engine_debug.h"

static void _ocf_read_wa_complete(struct ocf_request *req, int error)
{
	if (error)
		req->error |= error;

	if (env_atomic_dec_return(&req->req_remaining))
		return;

	if (req->error) {
		req->info.core_error = 1;
		env_atomic_inc(&req->core->counters->core_errors.write);
	}

	/* Complete request */
	req->complete(req, req->error);

	OCF_DEBUG_RQ(req, "Completion");

	/* Release OCF request */
	ocf_req_put(req);
}

int ocf_write_wa(struct ocf_request *req)
{
	struct ocf_cache *cache = req->cache;

	ocf_io_start(req->io);

	/* Get OCF request - increase reference counter */
	ocf_req_get(req);

	OCF_METADATA_LOCK_RD(); /*- Metadata RD access -----------------------*/

	/* Traverse request to check if there are mapped cache lines */
	ocf_engine_traverse(req);

	OCF_METADATA_UNLOCK_RD(); /*- END Metadata RD access -----------------*/

	if (ocf_engine_is_hit(req)) {
		ocf_req_clear(req);

		/* There is HIT, do WT */
		ocf_get_io_if(ocf_cache_mode_wt)->write(req);

	} else if (ocf_engine_mapped_count(req)) {
		ocf_req_clear(req);

		/* Partial MISS, do WI */
		ocf_get_io_if(ocf_cache_mode_wi)->write(req);
	} else {

		/* There is no mapped cache line, write directly into core */

		OCF_DEBUG_RQ(req, "Submit");

		/* Submit write IO to the core */
		env_atomic_set(&req->req_remaining, 1);
		ocf_submit_volume_req(&req->core->volume, req,
				_ocf_read_wa_complete);

		/* Update statistics */
		ocf_engine_update_block_stats(req);
		env_atomic64_inc(&req->core->counters->
			part_counters[req->part_id].write_reqs.pass_through);
	}

	/* Put OCF request - decrease reference counter */
	ocf_req_put(req);

	return 0;
}


