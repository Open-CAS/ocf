/*
 * Copyright(c) 2020-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf_seq_cutoff.h"
#include "ocf_cache_priv.h"
#include "ocf_core_priv.h"
#include "ocf_queue_priv.h"
#include "ocf_priv.h"
#include "utils/utils_cache_line.h"

void ocf_core_seq_cutoff_init(ocf_core_t core)
{
	if (ocf_core_get_seq_cutoff_policy(core)
			!= ocf_seq_cutoff_policy_never) {
		ocf_seq_detect_register_consumer(core->seq_detect);
		core->seq_cutoff_active = true;
	}
}

void ocf_core_seq_cutoff_deinit(ocf_core_t core)
{
	if (!core->seq_cutoff_active)
		return;

	ocf_seq_detect_unregister_consumer(core->seq_detect);
	core->seq_cutoff_active = false;
}

void ocf_seq_cutoff_set_policy(ocf_core_t core,
		ocf_seq_cutoff_policy policy)
{
	env_atomic_set(&core->conf_meta->seq_cutoff_policy, policy);

	if (!core->seq_cutoff_active
			&& policy != ocf_seq_cutoff_policy_never) {
		ocf_seq_detect_register_consumer(core->seq_detect);
		core->seq_cutoff_active = true;
	} else if (core->seq_cutoff_active
			&& policy == ocf_seq_cutoff_policy_never) {
		ocf_seq_detect_unregister_consumer(core->seq_detect);
		core->seq_cutoff_active = false;
	}
}

#define SEQ_CUTOFF_FULL_MARGIN 512

static inline bool ocf_seq_cutoff_is_on(ocf_cache_t cache,
		struct ocf_request *req)
{
	if (!ocf_cache_is_device_attached(cache))
		return false;

	return (ocf_lru_num_free(cache) <= SEQ_CUTOFF_FULL_MARGIN +
			req->core_line_count);
}

bool ocf_core_seq_cutoff_check(ocf_core_t core, struct ocf_request *req)
{
	ocf_seq_cutoff_policy policy = ocf_core_get_seq_cutoff_policy(core);
	uint32_t threshold = ocf_core_get_seq_cutoff_threshold(core);
	ocf_cache_t cache = ocf_core_get_cache(core);
	struct ocf_seq_detect_stream *stream;
	bool result;

	switch (policy) {
		case ocf_seq_cutoff_policy_always:
			break;
		case ocf_seq_cutoff_policy_full:
			if (ocf_seq_cutoff_is_on(cache, req))
				break;
			return false;

		case ocf_seq_cutoff_policy_never:
			return false;
		default:
			ENV_WARN(true, "Invalid sequential cutoff policy!");
			return false;
	}

	env_rwlock_read_lock(&req->io_queue->seq_detect->lock);
	stream = ocf_seq_detect_find(req->io_queue->seq_detect,
			req->addr, req->rw);
	result = stream && stream->bytes + req->bytes >= threshold;
	env_rwlock_read_unlock(&req->io_queue->seq_detect->lock);
	if (stream)
		return result;

	env_rwlock_read_lock(&core->seq_detect->lock);
	stream = ocf_seq_detect_find(core->seq_detect,
			req->addr, req->rw);
	result = stream && stream->bytes + req->bytes >= threshold;
	env_rwlock_read_unlock(&core->seq_detect->lock);

	if (stream)
		req->seq_cutoff_core = true;

	return result;
}

