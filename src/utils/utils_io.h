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

int ocf_submit_volume_flush_wait(ocf_volume_t volume);

int ocf_submit_volume_discard_wait(ocf_volume_t volume, uint64_t addr,
		uint64_t length);

int ocf_submit_write_zeroes_wait(ocf_volume_t volume, uint64_t addr,
		uint64_t length);

int ocf_submit_cache_page(struct ocf_cache *cache, uint64_t addr,
		int dir, void *buffer);

void ocf_submit_volume_req(ocf_volume_t volume, struct ocf_request *req,
		ocf_req_end_t callback);


void ocf_submit_cache_reqs(struct ocf_cache *cache,
		struct ocf_map_info *map_info, struct ocf_request *req, int dir,
		unsigned int reqs, ocf_req_end_t callback);

static inline struct ocf_io *ocf_new_cache_io(struct ocf_cache *cache)
{
	return ocf_volume_new_io(&cache->device->volume);
}

static inline struct ocf_io *ocf_new_core_io(struct ocf_cache *cache,
		ocf_core_id_t core_id)
{
	ENV_BUG_ON(core_id >= OCF_CORE_MAX);

	return ocf_volume_new_io(&cache->core[core_id].volume);
}

#endif /* UTILS_IO_H_ */
