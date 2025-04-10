/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ocf/ocf_types.h"
#include "../ocf_cache_priv.h"
#include "../utils/utils_user_part.h"
#include "ocf_partitions.h"

#define OCF_IO_CLASS_PRIORITY_DEFAULT 100

#define OCF_IO_CLASS_SWAP_NAME "SWAP"
#define OCF_IO_CLASS_SWAP_NAME_LEN env_strnlen(OCF_IO_CLASS_SWAP_NAME, OCF_IO_CLASS_NAME_MAX)
#define OCF_IO_CLASS_SWAP_MAX_SIZE 60
#define OCF_IO_CLASS_SWAP_MIN_SIZE 0
#define OCF_IO_CLASS_SWAP_CACHE_MODE ocf_cache_mode_wb
#define OCF_IO_CLASS_SWAP_PRIORITY OCF_IO_CLASS_PRIORITY_DEFAULT

#define OCF_IO_CLASS_PREFETCH_NAME "PREFETCH"
#define OCF_IO_CLASS_PREFETCH_NAME_LEN env_strnlen(OCF_IO_CLASS_PREFETCH_NAME, OCF_IO_CLASS_NAME_MAX)
/* prefetch partition size upper bound in 4KB cache lines (up to 20GB) */
#define OCF_IO_CLASS_PREFETCH_MAX_SIZE_CL ((1 << 18) * 20)
/* prefetch partition size upper bound in percentage of cache (10%) */
#define OCF_IO_CLASS_PREFETCH_MAX_SIZE_PCT 10
#define OCF_IO_CLASS_PREFETCH_MIN_SIZE 1
#define OCF_IO_CLASS_PREFETCH_CACHE_MODE ocf_cache_mode_wt
#define OCF_IO_CLASS_PREFETCH_PRIORITY OCF_IO_CLASS_PRIORITY_DEFAULT

#define	FRAC_TO_PCT	100	// Convert fraction to percent
#define MAX_SIZE_FOR_TESTING	100

uint8_t ocf_partitions_get_io_class(ocf_io_t io, ocf_core_t core)
{
	struct ocf_request *req = ocf_io_to_req(io);

	if (PA_ID_VALID_AND_REAL(req->io.pa_id))
		return OCF_IO_CLASS_ID_PREFETCH;

	return req->io.io_class;
}

/*
 * Computes n*a/b in uint32 arithmetics without integer overflow in the
 * intermediate value n*a.
 *
 * @returns n*a/b rounded down to the nearest integer
 */
static inline uint32_t frac_mult(uint32_t n, uint32_t a, uint32_t b)
{
	return (uint32_t)(((uint64_t)n * a) / b);
}

void ocf_partitions_update_prefetch_max_size(ocf_cache_t cache)
{
	struct ocf_user_part_config *prefetch =
		cache->user_parts[OCF_IO_CLASS_ID_PREFETCH].config;
	uint32_t total_clines = ocf_cache_get_line_count(cache);
	uint32_t max_cache_lines = OCF_IO_CLASS_PREFETCH_MAX_SIZE_CL /
		(ocf_cache_get_line_size(cache) / 4096);
	uint32_t clines_pct = frac_mult(total_clines,
		OCF_IO_CLASS_PREFETCH_MAX_SIZE_PCT, FRAC_TO_PCT);
	uint32_t max_size;

	if (clines_pct <= max_cache_lines) {
		max_size = OCF_IO_CLASS_PREFETCH_MAX_SIZE_PCT;
	} else {
		uint16_t min_size = prefetch->min_size;
		max_size = max_cache_lines * FRAC_TO_PCT / total_clines;
		if (max_size <= min_size)
			max_size = min_size + 1;
	}
	prefetch->max_size = max_size;
}

int ocf_partitions_config_predefined_partitions(ocf_cache_t cache)
{
	struct ocf_user_part_config *prefetch;

	/* update evict priority of io class 0 */
	cache->user_parts[0].config->priority = OCF_IO_CLASS_PRIORITY_DEFAULT;

	/* define PREFETCH io class */
	prefetch = cache->user_parts[OCF_IO_CLASS_ID_PREFETCH].config;
	if (env_strncpy(prefetch->name, OCF_IO_CLASS_NAME_MAX,
			OCF_IO_CLASS_PREFETCH_NAME, OCF_IO_CLASS_PREFETCH_NAME_LEN + 1))
		return -OCF_ERR_INVAL;
	prefetch->min_size = OCF_IO_CLASS_PREFETCH_MIN_SIZE;
	ocf_partitions_update_prefetch_max_size(cache);
	prefetch->priority = OCF_IO_CLASS_PREFETCH_PRIORITY;
	prefetch->cache_mode = OCF_IO_CLASS_PREFETCH_CACHE_MODE;
	ocf_user_part_set_valid(cache, OCF_IO_CLASS_ID_PREFETCH, !!cache->ocf_prefetcher);

	/* sort partitions */
	ocf_user_part_sort(cache);
	return 0;
}

int ocf_partitions_remove_predefined_partitions(ocf_cache_t cache)
{
	ocf_user_part_set_valid(cache, OCF_IO_CLASS_ID_SWAP, false);
	ocf_user_part_set_valid(cache, OCF_IO_CLASS_ID_PREFETCH, false);
	cache->user_parts[0].config->priority = OCF_IO_CLASS_PRIO_DEFAULT;
	ocf_user_part_sort(cache);
	return 0;
}
