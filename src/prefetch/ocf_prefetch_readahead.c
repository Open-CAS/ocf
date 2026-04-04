/*
 * Copyright(c) 2022-2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf_prefetch_readahead_priv.h"
#include "../ocf_cache_priv.h"
#include "../ocf_core_priv.h"
#include "../ocf_queue_priv.h"
#include "../ocf_seq_detect.h"
#include "../utils/utils_cache_line.h"
#include "ocf/ocf_def.h"
#include "ocf/prefetch/readahead.h"

#define OCF_PF_READAHEAD_MIN (64 * KiB)

static inline struct readahead_prefetch_policy_config *
ocf_pf_readahead_config(ocf_cache_t cache)
{
	return (void *)&cache->conf_meta->prefetch[ocf_pf_readahead].data;
}

void ocf_pf_readahead_setup(ocf_cache_t cache)
{
	struct readahead_prefetch_policy_config *config;

	config = ocf_pf_readahead_config(cache);
	config->threshold = OCF_PF_READAHEAD_DEFAULT_THRESHOLD;
}

int ocf_pf_readahead_set_param(ocf_cache_t cache, uint32_t param_id,
		uint32_t param_value)
{
	struct readahead_prefetch_policy_config *config;

	config = ocf_pf_readahead_config(cache);

	switch (param_id) {
	case ocf_readahead_threshold:
		if (param_value < OCF_PF_READAHEAD_MIN_THRESHOLD ||
				param_value > OCF_PF_READAHEAD_MAX_THRESHOLD) {
			ocf_cache_log(cache, log_err, "Refusing setting "
				"prefetch parameter because threshold is "
				"not within range of <%u-%u>\n",
				OCF_PF_READAHEAD_MIN_THRESHOLD,
				OCF_PF_READAHEAD_MAX_THRESHOLD);
			return -OCF_ERR_INVAL;
		}
		config->threshold = param_value;
		ocf_cache_log(cache, log_info, "Readahead prefetch "
				"threshold: %u\n", config->threshold);
		break;
	default:
		return -OCF_ERR_INVAL;
	}

	return 0;
}

int ocf_pf_readahead_get_param(ocf_cache_t cache, uint32_t param_id,
		uint32_t *param_value)
{
	struct readahead_prefetch_policy_config *config;

	config = ocf_pf_readahead_config(cache);

	switch (param_id) {
	case ocf_readahead_threshold:
		*param_value = config->threshold;
		break;
	default:
		return -OCF_ERR_INVAL;
	}

	return 0;
}

int ocf_pf_readahead_init(ocf_core_t core)
{
	ocf_seq_detect_register_consumer(core->seq_detect);
	core->pf_priv[ocf_pf_readahead] = core;
	return 0;
}

void ocf_pf_readahead_deinit(ocf_core_t core)
{
	if (!core->pf_priv[ocf_pf_readahead])
		return;

	ocf_seq_detect_unregister_consumer(core->seq_detect);
	core->pf_priv[ocf_pf_readahead] = NULL;
}

void ocf_pf_readahead_get_range(struct ocf_request *req,
		struct ocf_pf_range *range)
{
	struct ocf_seq_detect *queue_sd = req->io_queue->seq_detect;
	struct ocf_seq_detect *core_sd = req->core->seq_detect;
	struct ocf_seq_detect_stream *stream;
	uint64_t bytes = 0;

	range->core_line_first = 0;
	range->core_line_count = 0;

	/* Check queue-level detector first, then core-level */
	env_rwlock_read_lock(&queue_sd->lock);
	stream = ocf_seq_detect_find(queue_sd, req->addr, req->rw);
	if (stream)
		bytes = stream->bytes;
	env_rwlock_read_unlock(&queue_sd->lock);

	if (!stream) {
		env_rwlock_read_lock(&core_sd->lock);
		stream = ocf_seq_detect_find(core_sd, req->addr, req->rw);
		if (stream)
			bytes = stream->bytes;
		env_rwlock_read_unlock(&core_sd->lock);
	}

	if (!stream)
		return;

	if (bytes < ocf_pf_readahead_config(req->cache)->threshold)
		return;

	range->core_line_first = req->core_line_first + req->core_line_count;
	range->core_line_count = OCF_MAX(req->core_line_count,
			ocf_bytes_2_lines(req->cache, OCF_PF_READAHEAD_MIN));
}
