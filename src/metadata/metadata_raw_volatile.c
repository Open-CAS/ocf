/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "metadata.h"
#include "metadata_hash.h"
#include "metadata_raw.h"
#include "metadata_io.h"
#include "metadata_raw_volatile.h"

/*
 * RAW volatile Implementation - Size on SSD
 */
uint32_t raw_volatile_size_on_ssd(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	return 0;
}

/*
 * RAW volatile Implementation - Checksum
 */
uint32_t raw_volatile_checksum(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	return 0;
}

/*
 * RAW volatile Implementation - Flush specified element to SSD
 */
int raw_volatile_flush(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line)
{
	return 0;
}

/*
 * RAW volatile Implementation - Load all metadata elements from SSD
 */
int raw_volatile_load_all(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	return -ENOTSUP;
}

/*
 * RAM Implementation - Flush all elements
 */
int raw_volatile_flush_all(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw)
{
	return 0;
}

/*
 * RAM RAM Implementation - Mark to Flush
 */
void raw_volatile_flush_mark(struct ocf_cache *cache, struct ocf_request *rq,
		uint32_t map_idx, int to_state, uint8_t start, uint8_t stop)
{
}

/*
 * RAM RAM Implementation - Do Flush asynchronously
 */
int raw_volatile_flush_do_asynch(struct ocf_cache *cache,
		struct ocf_request *rq, struct ocf_metadata_raw *raw,
		ocf_req_end_t complete)
{
	complete(rq, 0);
	return 0;
}
