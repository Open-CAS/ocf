/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "../ocf_core_priv.h"
#include "ocf_prefetch.h"

#include "ocf_env.h"
#include "ocf_prefetch_priv.h"
#include "ocf_prefetch_stream.h"
#include "ocf_prefetch_naive.h"
#include "ocf/ocf_prefetch_common.h"
#include "ocf/ocf_blktrace.h"
#include "engine_prefetch.h"

#include "../metadata/metadata.h"
#include "../utils/utils_cache_line.h"
#include "../ocf_cache_priv.h"
#include "../ocf_core_priv.h"
#include "../ocf_def_priv.h"
#include "../ocf_request.h"

/* ===========================================================================*/

#define OCF_OCF_PREFETCH_DEBUG 0

#if 1 == OCF_OCF_PREFETCH_DEBUG
#define OCF_DEBUG_TRACE(core) \
       ocf_core_log(core, log_info, "[OCF][Prefetch] %s\n", __func__)

#define OCF_DEBUG_PARAM(core, format, ...) \
       ocf_core_log(core, log_info, "[OCF][Prefetch] %s(%d) - "format"\n", \
                       __func__, __LINE__, ##__VA_ARGS__)
#else
#define OCF_DEBUG_TRACE(core)
#define OCF_DEBUG_PARAM(core, format, ...)
#endif

/* ===========================================================================*/

typedef struct {
	ocf_pf_req_info_t req_parts[pa_id_num];
	uint8_t num_parts;
} ocf_pf_req_parts_info_t;

/* ===========================================================================*/
static void prefetch_complete(struct ocf_request *req, int error)
{
	if (ocf_cache_ml_is_upper(req->cache))
		OCF_BLKTRACE_COMPLETE_IO(req);
	ocf_req_put(req);
}

/* ===========================================================================*/
/* Call the relevant Prefetch algorithm and get the prefetch info */
static void get_prefetch_info(uint8_t pf_algo_id_mask, struct ocf_request *req,
					ocf_pf_req_parts_info_t *req_parts_info)
{
	static void (*get_info[])(ocf_prefetch_t pf,
						ocf_pf_req_info_t *req_info) = {
		#define X(alg) ocf_pf_##alg##_get_info,
		OCF_PF_ALGOS_X
		#undef X
	};
	pf_algo_id_t pa_id;

	/* initialize output: no valid results yet */
	req_parts_info->num_parts = 0;

	for_each_enabled_pa_id(pa_id, pf_algo_id_mask) {
		/* initialize input to prefetchers as triggering request's address and length */
		ocf_pf_req_info_t *req_info = &req_parts_info->req_parts[req_parts_info->num_parts];
		req_info->addr = req->addr;
		req_info->len  = req->bytes;
		req_info->pa_id = pa_id_none;

		/* call prefetcher */
		get_info[pa_id](req->core->ocf_prefetch_handles[pa_id], req_info);
		if (!PA_ID_VALID(req_info->pa_id))
			continue;

		req_parts_info->num_parts++;
	}
}

static bool is_hit(ocf_cache_t pf_cache, struct ocf_request *req, uint64_t addr)
{
	ocf_cache_t cache = req->cache;
	ocf_core_t core = req->core;

	while(cache != NULL && core != NULL) {
		if (ocf_metadata_is_hit_no_lock(cache, ocf_core_get_id(core),
				ocf_bytes_2_lines(cache, addr))) {
			return true;
		}
		if (cache == pf_cache) {
			return false;
		}
		cache = ocf_cache_ml_get_lower_cache(cache);
		core = ocf_cache_ml_get_lower_core(core);
	}

	return false;
}

/* ===========================================================================*/
/* Update the request address and size to contain only a heuristic sequence */
/* of data that isn't in the cache */
#define MAX_SKIP_CL	(8)
static uint32_t get_pf_req_info(ocf_cache_t pf_cache, struct ocf_request *req,
						uint64_t *byte_position, uint32_t len, uint32_t maxlen)
{
	uint64_t addr;
	uint32_t byte_length = ocf_cache_get_line_size(pf_cache);
	uint64_t first_addr = *byte_position;
	uint64_t last_addr = first_addr + len;
	uint64_t first_miss_addr = 0, last_miss_addr = 0;	/* 0 can't be a valid prefetch address */

	int64_t skip = ocf_bytes_2_lines(pf_cache, OCF_MIN(len, maxlen)) - 1;
	skip = OCF_MIN(skip, MAX_SKIP_CL);
	skip = OCF_MAX(skip, 1);
	skip = ocf_lines_2_bytes(pf_cache, skip);

	for (addr = first_addr; addr < last_addr; addr += skip) {
		if (is_hit(pf_cache, req, addr)) {
			if (first_miss_addr)
				break;
		} else {
			if (!first_miss_addr) {
				first_miss_addr = addr;
				last_addr = OCF_MIN(last_addr, first_miss_addr + maxlen);
			}

			last_miss_addr = addr;
		}
	}

	if (first_miss_addr) {
		if ((first_miss_addr - first_addr) > byte_length) {
			/* Need to find the correct first miss address */
			*byte_position = first_miss_addr - skip + byte_length;
			len = skip - byte_length;
			first_miss_addr -= get_pf_req_info(pf_cache, req, byte_position, len, len);
			last_addr = OCF_MIN(last_addr, first_miss_addr + maxlen);
			last_miss_addr = OCF_MIN(last_miss_addr, last_addr - byte_length);
		}

		if ((last_addr - last_miss_addr) > byte_length) {
			/* Need to find the correct last miss address */
			*byte_position = last_miss_addr + byte_length;
			len = last_addr - *byte_position;
			last_miss_addr += get_pf_req_info(pf_cache, req, byte_position, len, len);
		}

		*byte_position = first_miss_addr;
		return last_miss_addr + byte_length - first_miss_addr;
	}

	return 0;
}

/* ===========================================================================*/
/* Create the prefetch database per core */
void ocf_prefetch_create(ocf_core_t core)
{
	/* Add here the create functions (if needed) for the prefetch algorithms */
	static void (*create[])(ocf_core_t core) = {
		ocf_pf_stream_create
	};

	uint i;
	if (unlikely(core == NULL)) {
		ENV_WARN(true, "Core Handle is NULL\n");
		return;
	}
	/* Create all the prefetch algorithm that need create */
	for (i = 0; i < ARRAY_SIZE(create); i++) {
		create[i](core);
	}
}

/* ===========================================================================*/
/* Destroy the prefetch database per core */
void ocf_prefetch_destroy(ocf_core_t core)
{
	/* Add here the destroy functions (if needed) for the prefetch algorithms */
	static void (*destroy[])(ocf_core_t core) = {
		ocf_pf_stream_destroy
	};
	uint i = 0;

	if (unlikely(core == NULL)) {
		ENV_WARN(true, "Core Handle is NULL\n");
		return;
	}
	/* Destroy all the prefetch algorithm that need destroy */
	for (i = 0; i < ARRAY_SIZE(destroy); i++) {
		destroy[i](core);
	}
}

/* ===========================================================================
 * If a lower cache exists, any prefetch address higher than this address
 * will be prefetched to the lower cache
 * #define	PF_TO_LOWER_CACHE_TRIGGER_ADDR(_req)	((_req)->byte_position + (_req)->byte_length * 4)
 */
#define	PF_TO_LOWER_CACHE_TRIGGER_ADDR(_req)	(~(uint64_t)0)

static void ocf_prefetch_part(struct ocf_request *req, uint8_t io_class,
		ocf_pf_req_info_t *req_info)
{
	uint64_t byte_position;
	struct ocf_request *prefetch_req = NULL;
	uint64_t last_addr;
	uint32_t len = 0, total_len = 0;
	ocf_cache_t lower_cache = ocf_cache_ml_get_lower_cache(req->cache);
	uint32_t maxlen = ocf_lines_2_bytes(req->cache, ocf_bytes_round_lines(req->cache, MAX_SINGLE_PF(req->bytes)));
	uint64_t pf_to_lower_trigger_addr = PF_TO_LOWER_CACHE_TRIGGER_ADDR(req);

	/* round address down to whole line size */
	req_info->addr = ocf_lines_2_bytes(req->cache, ocf_bytes_round_lines(req->cache, req_info->addr));
	/* round length up to whole line size */
	req_info->len = ocf_lines_2_bytes(req->cache, ocf_bytes_2_lines_round_up(req->cache, req_info->len));

	/* Abort if request exceeds backend volume size */
	if (unlikely(req_info->addr >= ocf_volume_get_length(req->core->volume))) {
		return;
	}

	/* Trim the len not to exceed backend volume size */
	req_info->len = OCF_MIN(req_info->len,
				ocf_volume_get_length(req->core->volume) - req_info->addr);

	OCF_DEBUG_PARAM(req->core, "pa_id=%u,addr=%lu,len=%d",
		req_info->pa_id, req_info->addr, req_info->len);

	byte_position = req_info->addr;
	last_addr = req_info->addr + req_info->len;

	while (byte_position < last_addr) {
		ocf_core_t pf_core;
		ocf_queue_t pf_queue;
		ocf_cache_t pf_cache = (lower_cache && byte_position > pf_to_lower_trigger_addr)
								? lower_cache : req->cache;

		if ((len = get_pf_req_info(pf_cache, req, &byte_position, last_addr - byte_position, maxlen)) == 0)
			break;

		if (pf_cache == lower_cache)
			pf_core = ocf_cache_ml_get_lower_core(req->core);
		else
			pf_core = req->core;
		pf_queue = req->io_queue;
		prefetch_req = ocf_req_new_extended(pf_queue, pf_core,
							byte_position, len, OCF_READ);

		if (unlikely(prefetch_req == NULL)) {
			ENV_WARN(true, "ocf_new_req(addr = 0x%p, len = 0x%x) failed\n",
					(void *)byte_position, len);
			break;
		}
		prefetch_req->io.volume = req->io.volume;
		prefetch_req->io.io_class = req->io.io_class;
		prefetch_req->flags = req->flags;
		prefetch_req->io.pa_id = req_info->pa_id;

		prefetch_req->complete = prefetch_complete;

		OCF_BLKTRACE_NEW_OCF_REQ(prefetch_req, req);

		ocf_prefetch_read(prefetch_req);

		total_len += len;
		if (total_len >= MAX_TOTAL_PF)
			break;

		byte_position += len;
		maxlen = OCF_MIN(maxlen, ocf_lines_2_bytes(req->cache, ocf_bytes_round_lines(req->cache, MAX_TOTAL_PF - total_len)));
	}
}

void ocf_prefetch(struct ocf_request *req)
{
	int i;
	ocf_pf_req_parts_info_t req_parts_info;

	ENV_BUILD_BUG_ON(OCF_PA_ID_MAX <= PA_MASK_LAST_BIT);

	/* Check Parameters */
	if (unlikely(req == NULL)) {
		ENV_WARN(true, "req is NULL\n");
		return;
	}
	if (unlikely(req->core == NULL)) {
		ENV_WARN(true, "req->core are NULL\n");
		return;
	}

	/* Return if the request isn't a candidate for prefetch */
	if (req->rw != OCF_READ || PA_ID_VALID(req->io.pa_id)) {
		return;
	}

	if (req->cache_mode != ocf_req_cache_mode_wt
			&& req->cache_mode != ocf_req_cache_mode_fast)
		return;

	/* Get the prefetch info */
	get_prefetch_info(req->core->ocf_prefetcher, req, &req_parts_info);

	/* process suggestions and trigger prefetch-core-read requests */
	for (i = 0; i < req_parts_info.num_parts; i++) {
		ocf_prefetch_part(req, req->io.io_class, &req_parts_info.req_parts[i]);
	}
}
