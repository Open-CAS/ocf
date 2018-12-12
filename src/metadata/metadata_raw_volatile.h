/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_RAW_VOLATILE_H__
#define __METADATA_RAW_VOLATILE_H__

/*
 * RAW volatile Implementation - Size on SSD
 */
uint32_t raw_volatile_size_on_ssd(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAW volatile Implementation - Checksum
 */
uint32_t raw_volatile_checksum(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAW volatile Implementation - Flush specified element to SSD
 */
int raw_volatile_flush(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line);

/*
 * RAW volatile Implementation - Load all metadata elements from SSD
 */
int raw_volatile_load_all(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAW volatile Implementation - Flush all elements
 */
int raw_volatile_flush_all(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAM RAW volatile Implementation - Mark to Flush
 */
void raw_volatile_flush_mark(struct ocf_cache *cache, struct ocf_request *req,
		uint32_t map_idx, int to_state, uint8_t start, uint8_t stop);

/*
 * RAM RAW volatile Implementation - Do Flush asynchronously
 */
int raw_volatile_flush_do_asynch(struct ocf_cache *cache,
		struct ocf_request *req, struct ocf_metadata_raw *raw,
		ocf_req_end_t complete);

#endif /* __METADATA_RAW_VOLATILE_H__ */
