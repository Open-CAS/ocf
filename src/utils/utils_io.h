/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef UTILS_IO_H_
#define UTILS_IO_H_

#include "../ocf_request.h"

/**
 * Checks if 2 IOs are overlapping.
 * @param start1 start of first range (inclusive)
 * @param end1 end of first range (exclusive)
 * @param start2 start of second range (inclusive)
 * @param end2 end of second range (exclusive)
 * @return 0 in case overlap is not detected, otherwise 1
 */
static inline int ocf_io_range_overlaps(uint32_t start1, uint32_t end1,
		uint32_t start2, uint32_t end2)
{
	if (start2 <= start1 && end2 >= start1)
		return 1;

	if (start2 >= start1 && end1 >= start2)
		return 1;

	return 0;
}

/**
 * Checks if 2 IOs are overlapping.
 * @param start1 start of first range (inclusive)
 * @param count1 no of bytes, cachelines (etc) for first range
 * @param start2 start of second range (inclusive)
 * @param count2 no of bytes, cachelines (etc) for second range
 * @return 0 in case overlap is not detected, otherwise 1
 */
static inline int ocf_io_overlaps(uint32_t start1, uint32_t count1,
		uint32_t start2, uint32_t count2)
{
	return ocf_io_range_overlaps(start1, start1 + count1 - 1, start2,
			start2 + count2 - 1);
}

int ocf_submit_io_wait(struct ocf_io *io);

void ocf_submit_obj_flush(ocf_data_obj_t obj, ocf_end_t callback,
		void *context);

int ocf_submit_obj_flush_wait(ocf_data_obj_t obj);

int ocf_submit_obj_discard_wait(ocf_data_obj_t obj, uint64_t addr,
		uint64_t length);

void ocf_submit_obj_discard(ocf_data_obj_t obj, struct ocf_request *req,
		ocf_end_t callback, void *ctx);

int ocf_submit_write_zeroes_wait(ocf_data_obj_t obj, uint64_t addr,
		uint64_t length);

int ocf_submit_cache_page(struct ocf_cache *cache, uint64_t addr,
		int dir, void *buffer);

void ocf_submit_obj_req(ocf_data_obj_t obj, struct ocf_request *req,
		int dir, ocf_end_t callback, void *ctx);


void ocf_submit_cache_reqs(struct ocf_cache *cache,
		struct ocf_map_info *map_info, struct ocf_request *req, int dir,
		unsigned int reqs, ocf_end_t callback, void *ctx);

static inline struct ocf_io *ocf_new_cache_io(struct ocf_cache *cache)
{
	return ocf_dobj_new_io(&cache->device->obj);
}

static inline struct ocf_io *ocf_new_core_io(struct ocf_cache *cache,
		ocf_core_id_t core_id)
{
	ENV_BUG_ON(core_id >= OCF_CORE_MAX);

	return ocf_dobj_new_io(&cache->core_obj[core_id].obj);
}

#endif /* UTILS_IO_H_ */
