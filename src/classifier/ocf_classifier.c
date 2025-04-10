/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../ocf_request.h"
#include "../ocf_cache_priv.h"
#include "../ocf_core_priv.h"
#include "../utils/utils_user_part.h"
#include "ocf_classifier.h"

/* The threshold (in power of 2) for cache occupancy.
 * If occupancy is lower, then don't activate the write admission control. */
#define CACHE_OCCUPANCY_THRESHOLD	7

void ocf_classifier(struct ocf_request *req)
{
	int i, wa_check = 0, wa_result = 0;
	bool (*wac_algs_arr[]) (struct ocf_request *req) = {
		NULL,           // OCF_CLASSIFIER_IGNORE_OCF placeholder
		NULL,           // OCF_CLASSIFIER_SWAP placeholder
		#define X(classifier)	ocf_classifier_##classifier,
		OCF_CLASSIFIER_HANDLERS_X
		#undef X
	};

	for (i = 0; i < (ARRAY_SIZE(wac_algs_arr)); i++)
		if ((req->core->ocf_classifier & (1<<i)) && wac_algs_arr[i]) {
			wa_check |= (1 << i);
			if (wac_algs_arr[i](req))
				wa_result |= (1 << i);
		}

	/* READ request - not subject to write admission */
	if (req->rw == OCF_READ)
		return;

	/* No conditional WA to be checked OR result not equal to goal */
	if (!wa_check || wa_check != wa_result)
		return;

	/* Cache not full */
	if (ocf_part_get_occupancy(&req->cache->free) >
	    (ocf_cache_get_line_count(req->cache) >> CACHE_OCCUPANCY_THRESHOLD))
		return;

	req->cache_mode = ocf_req_cache_mode_pt;
}
