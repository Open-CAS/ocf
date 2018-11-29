/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "../ocf_cache_priv.h"
#include "../ocf_ctx_priv.h"
#include "engine_bf.h"
#include "engine_inv.h"
#include "engine_common.h"
#include "cache_engine.h"
#include "../utils/utils_rq.h"
#include "../utils/utils_io.h"
#include "../concurrency/ocf_concurrency.h"

#define OCF_ENGINE_DEBUG_IO_NAME "bf"
#include "engine_debug.h"

/* Decrements and checks if queue may be unblocked again */
static inline void backfill_queue_dec_unblock(struct ocf_cache *cache)
{
	env_atomic_dec(&cache->pending_read_misses_list_count);

	if (!env_atomic_read(&cache->pending_read_misses_list_blocked))
		return;

	if (env_atomic_read(&cache->pending_read_misses_list_count)
			< cache->backfill.queue_unblock_size)
		env_atomic_set(&cache->pending_read_misses_list_blocked, 0);
}

static inline void backfill_queue_inc_block(struct ocf_cache *cache)
{
	if (env_atomic_inc_return(&cache->pending_read_misses_list_count)
			>= cache->backfill.max_queue_size)
		env_atomic_set(&cache->pending_read_misses_list_blocked, 1);
}

static void _ocf_backfill_do_io(void *private_data, int error)
{
	struct ocf_request *rq = (struct ocf_request *)private_data;
	struct ocf_cache *cache = rq->cache;

	if (error)
		rq->error = error;

	if (rq->error)
		inc_fallback_pt_error_counter(rq->cache);

	/* Handle callback-caller race to let only one of the two complete the
	 * request. Also, complete original request only if this is the last
	 * sub-request to complete
	 */
	if (env_atomic_dec_return(&rq->req_remaining) == 0) {
		/* We must free the pages we have allocated */
		ctx_data_secure_erase(cache->owner, rq->data);
		ctx_data_munlock(cache->owner, rq->data);
		ctx_data_free(cache->owner, rq->data);
		rq->data = NULL;

		if (rq->error) {
			env_atomic_inc(&cache->core_obj[rq->core_id].
					counters->cache_errors.write);
			ocf_engine_invalidate(rq);
		} else {
			ocf_rq_unlock(rq);

			/* always free the request at the last point
			 * of the completion path
			 */
			ocf_rq_put(rq);
		}
	}
}

static int _ocf_backfill_do(struct ocf_request *rq)
{
	unsigned int reqs_to_issue;

	backfill_queue_dec_unblock(rq->cache);

	reqs_to_issue = ocf_engine_io_count(rq);

	/* There will be #reqs_to_issue completions */
	env_atomic_set(&rq->req_remaining, reqs_to_issue);

	rq->data = rq->cp_data;

	ocf_submit_cache_reqs(rq->cache, rq->map, rq, OCF_WRITE, reqs_to_issue,
			      _ocf_backfill_do_io, rq);

	return 0;
}

static const struct ocf_io_if _io_if_backfill = {
	.read = _ocf_backfill_do,
	.write = _ocf_backfill_do,
};

void ocf_engine_backfill(struct ocf_request *rq)
{
	backfill_queue_inc_block(rq->cache);
	ocf_engine_push_rq_front_if(rq, &_io_if_backfill, true);
}
