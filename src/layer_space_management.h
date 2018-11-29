/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#ifndef __LAYER_SPACE_MANAGEMENT_H__

#define __LAYER_SPACE_MANAGEMENT_H__

#include "ocf_request.h"

#define OCF_TO_EVICTION_MIN 128UL

/*
 * Deallocates space from low priority partitions.
 *
 * Returns -1 on error
 * or the destination partition ID for the free buffers
 * (it matches label and is part of the object (#core_id) IO group)
 */
int space_managment_evict_do(struct ocf_cache *cache,
		struct ocf_request *req, uint32_t evict_cline_no);

int space_management_free(struct ocf_cache *cache, uint32_t count);

#endif
