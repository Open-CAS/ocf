/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "nhit_hash.h"
#include "../../metadata/metadata.h"
#include "../../ocf_priv.h"
#include "../../engine/engine_common.h"

#include "nhit.h"
#include "../ops.h"

#define NHIT_MAPPING_RATIO 2

struct nhit_policy_context {
	nhit_hash_t hash_map;

	/* Configurable parameters */
	env_atomic insertion_threshold;
	env_atomic64 trigger_threshold;
};

ocf_error_t nhit_init(ocf_cache_t cache, ocf_promotion_policy_t policy)
{
	struct nhit_policy_context *ctx;
	int result = 0;

	ctx = env_vmalloc(sizeof(*ctx));
	if (!ctx) {
		result = -OCF_ERR_NO_MEM;
		goto exit;
	}

	result = nhit_hash_init(ocf_metadata_get_cachelines_count(cache) *
			NHIT_MAPPING_RATIO, &ctx->hash_map);
	if (result)
		goto dealloc_ctx;

	env_atomic_set(&ctx->insertion_threshold, NHIT_THRESHOLD_DEFAULT);
	env_atomic64_set(&ctx->trigger_threshold,
			OCF_DIV_ROUND_UP((NHIT_TRIGGER_DEFAULT *
			 ocf_metadata_get_cachelines_count(cache)), 100));

	policy->ctx = ctx;

	return 0;

dealloc_ctx:
	env_vfree(ctx);
exit:
	ocf_cache_log(cache, log_err, "Error initializing nhit promotion policy\n");
	return result;
}

void nhit_deinit(ocf_promotion_policy_t policy)
{
	struct nhit_policy_context *ctx = policy->ctx;

	nhit_hash_deinit(ctx->hash_map);

	env_vfree(ctx);
	policy->ctx = NULL;
}

ocf_error_t nhit_set_param(ocf_promotion_policy_t policy, uint8_t param_id,
		uint64_t param_value)
{
	struct nhit_policy_context *ctx = policy->ctx;
	ocf_error_t result = 0;

	switch (param_id) {
	case nhit_insertion_threshold:
		if (param_value >= NHIT_MIN_THRESHOLD &&
				param_value < NHIT_MAX_THRESHOLD) {
			env_atomic_set(&ctx->insertion_threshold, param_value);
		} else {
			ocf_cache_log(policy->owner, log_err, "Invalid nhit "
					"promotion policy insertion threshold!\n");
			result = -OCF_ERR_INVAL;
		}
		break;

	case nhit_trigger_threshold:
		if (param_value >= NHIT_MIN_TRIGGER &&
				param_value < NHIT_MAX_TRIGGER) {
			env_atomic64_set(&ctx->trigger_threshold,
				OCF_DIV_ROUND_UP((param_value *
				ocf_metadata_get_cachelines_count(policy->owner)),
				100));

		} else {
			ocf_cache_log(policy->owner, log_err, "Invalid nhit "
					"promotion policy insertion trigger "
					"threshold!\n");
			result = -OCF_ERR_INVAL;
		}
		break;

	default:
		ocf_cache_log(policy->owner, log_err, "Invalid nhit "
				"promotion policy parameter (%u)!\n",
				param_id);
		result = -OCF_ERR_INVAL;

		break;
	}

	return result;
}

ocf_error_t nhit_get_param(ocf_promotion_policy_t policy, uint8_t param_id,
		uint64_t *param_value)
{
	struct nhit_policy_context *ctx = policy->ctx;
	ocf_error_t result = 0;

	OCF_CHECK_NULL(param_value);

	switch (param_id) {
	case nhit_insertion_threshold:
		*param_value = env_atomic_read(&ctx->insertion_threshold);
		break;

	default:
		ocf_cache_log(policy->owner, log_err, "Invalid nhit "
				"promotion policy parameter (%u)!\n",
				param_id);
		result = -OCF_ERR_INVAL;

		break;
	}

	return result;
}

static void core_line_purge(struct nhit_policy_context *ctx, ocf_core_id_t core_id,
		uint64_t core_lba)
{
	nhit_hash_set_occurences(ctx->hash_map, core_id, core_lba, 0);
}

void nhit_req_purge(ocf_promotion_policy_t policy,
		struct ocf_request *req)
{
	struct nhit_policy_context *ctx = policy->ctx;
	uint32_t i;
	uint64_t core_line;

	for (i = 0, core_line = req->core_line_first;
			core_line <= req->core_line_last; core_line++, i++) {
		struct ocf_map_info *entry = &(req->map[i]);

		core_line_purge(ctx, entry->core_id, entry->core_line);
	}
}

static bool core_line_should_promote(struct nhit_policy_context *ctx,
		ocf_core_id_t core_id, uint64_t core_lba)
{
	bool hit;
	int32_t counter;

	hit = nhit_hash_query(ctx->hash_map, core_id, core_lba, &counter);
	if (hit) {
		/* we have a hit, return now */
		return env_atomic_read(&ctx->insertion_threshold) <= counter;
	}

	nhit_hash_insert(ctx->hash_map, core_id, core_lba);

	return false;
}

bool nhit_req_should_promote(ocf_promotion_policy_t policy,
		struct ocf_request *req)
{
	struct nhit_policy_context *ctx = policy->ctx;
	bool result = true;
	uint32_t i;
	uint64_t core_line;
	uint64_t occupied_cachelines =
		ocf_metadata_get_cachelines_count(policy->owner) -
		ocf_freelist_num_free(policy->owner->freelist);

	if (occupied_cachelines > env_atomic64_read(&ctx->trigger_threshold))
		return true;

	for (i = 0, core_line = req->core_line_first;
			core_line <= req->core_line_last; core_line++, i++) {
		struct ocf_map_info *entry = &(req->map[i]);

		if (!core_line_should_promote(ctx, entry->core_id,
					entry->core_line)) {
			result = false;
		}
	}

	/* We don't want to reject even partially
	 * hit requests - this way we could trigger passthrough and invalidation.
	 * Let's let it in! */
	return result || req->info.hit_no;
}

