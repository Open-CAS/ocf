/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "metadata.h"
#include "metadata_io.h"
#include "metadata_updater_priv.h"
#include "../ocf_priv.h"
#include "../engine/engine_common.h"
#include "../ocf_cache_priv.h"
#include "../ocf_ctx_priv.h"
#include "../utils/utils_io.h"

int ocf_metadata_updater_init(ocf_cache_t cache)
{
	ocf_metadata_updater_t mu = &cache->metadata_updater;
	struct ocf_metadata_io_syncher *syncher = &mu->syncher;

	INIT_LIST_HEAD(&syncher->in_progress_head);
	INIT_LIST_HEAD(&syncher->pending_head);
	env_mutex_init(&syncher->lock);

	return ctx_metadata_updater_init(cache->owner, mu);
}

void ocf_metadata_updater_kick(ocf_cache_t cache)
{
	ctx_metadata_updater_kick(cache->owner, &cache->metadata_updater);
}

void ocf_metadata_updater_stop(ocf_cache_t cache)
{
	ctx_metadata_updater_stop(cache->owner, &cache->metadata_updater);
	env_mutex_destroy(&cache->metadata_updater.syncher.lock);
}

void ocf_metadata_updater_set_priv(ocf_metadata_updater_t mu, void *priv)
{
	OCF_CHECK_NULL(mu);
	mu->priv = priv;
}

void *ocf_metadata_updater_get_priv(ocf_metadata_updater_t mu)
{
	OCF_CHECK_NULL(mu);
	return mu->priv;
}

ocf_cache_t ocf_metadata_updater_get_cache(ocf_metadata_updater_t mu)
{
	OCF_CHECK_NULL(mu);
	return container_of(mu, struct ocf_cache, metadata_updater);
}

static int _metadata_updater_iterate_in_progress(ocf_cache_t cache,
		struct list_head *finished, struct metadata_io_request *new_req)
{
	struct ocf_metadata_io_syncher *syncher =
			&cache->metadata_updater.syncher;
	struct metadata_io_request *curr, *temp;

	list_for_each_entry_safe(curr, temp, &syncher->in_progress_head, list) {
		if (env_atomic_read(&curr->finished)) {
			list_move_tail(&curr->list, finished);
			continue;
		}
		if (new_req) {
			/* If request specified, check if overlap occurs. */
			if (ocf_io_overlaps(new_req->page, new_req->count,
					curr->page, curr->count)) {
				return 1;
			}
		}
	}

	return 0;
}

static void metadata_updater_process_finished(struct list_head *finished)
{
	struct metadata_io_request *curr, *temp;

	list_for_each_entry_safe(curr, temp, finished, list) {
		list_del(&curr->list);
		metadata_io_req_complete(curr);
	}
}

void metadata_updater_submit(struct metadata_io_request *m_req)
{
	ocf_cache_t cache = m_req->cache;
	struct ocf_metadata_io_syncher *syncher =
			&cache->metadata_updater.syncher;
	struct list_head finished;
	int ret;

	INIT_LIST_HEAD(&finished);

	env_mutex_lock(&syncher->lock);

	ret = _metadata_updater_iterate_in_progress(cache, &finished, m_req);

	/* Either add it to in-progress list or pending list for deferred
	 * execution.
	 */
	if (ret == 0)
		list_add_tail(&m_req->list, &syncher->in_progress_head);
	else
		list_add_tail(&m_req->list, &syncher->pending_head);

	env_mutex_unlock(&syncher->lock);

	if (ret == 0)
		ocf_engine_push_req_front(&m_req->req, true);

	metadata_updater_process_finished(&finished);
}

uint32_t ocf_metadata_updater_run(ocf_metadata_updater_t mu)
{
	struct metadata_io_request *curr, *temp;
	struct ocf_metadata_io_syncher *syncher;
	struct list_head finished;
	ocf_cache_t cache;
	int ret;

	OCF_CHECK_NULL(mu);

	INIT_LIST_HEAD(&finished);

	cache = ocf_metadata_updater_get_cache(mu);
	syncher = &cache->metadata_updater.syncher;

	env_mutex_lock(&syncher->lock);
	if (list_empty(&syncher->pending_head)) {
		/*
		 * If pending list is empty, we iterate over in progress
		 * list to free memory used by finished requests.
		 */
		_metadata_updater_iterate_in_progress(cache, &finished, NULL);
		env_mutex_unlock(&syncher->lock);
		metadata_updater_process_finished(&finished);
		env_cond_resched();
		return 0;
	}
	list_for_each_entry_safe(curr, temp, &syncher->pending_head, list) {
		ret = _metadata_updater_iterate_in_progress(cache, &finished, curr);
		if (ret == 0) {
			/* Move to in-progress list and kick the workers */
			list_move_tail(&curr->list, &syncher->in_progress_head);
		}
		env_mutex_unlock(&syncher->lock);
		metadata_updater_process_finished(&finished);
		if (ret == 0)
			ocf_engine_push_req_front(&curr->req, true);
		env_cond_resched();
		env_mutex_lock(&syncher->lock);
	}
	env_mutex_unlock(&syncher->lock);

	return 0;
}
