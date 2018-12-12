/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_RAW_DYNAMIC_H__
#define __METADATA_RAW_DYNAMIC_H__

/**
 * @file metadata_raw_dynamic.h
 * @brief Metadata RAW container implementation for dynamic numbers of elements
 */

/*
 * RAW DYNAMIC - Initialize
 */
int raw_dynamic_init(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAW DYNAMIC - De-Initialize
 */
int raw_dynamic_deinit(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAW DYNAMIC - Get size of memory footprint of this RAW metadata container
 */
size_t raw_dynamic_size_of(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAW DYNAMIC Implementation - Size on SSD
 */
uint32_t raw_dynamic_size_on_ssd(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAW DYNAMIC Implementation - Checksum
 */
uint32_t raw_dynamic_checksum(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAW DYNAMIC - Get specified entry
 */
int raw_dynamic_get(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		void *data, uint32_t size);

/*
 * RAW DYNAMIC - Set specified entry
 */
int raw_dynamic_set(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		void *data, uint32_t size);

/*
 * RAW DYNAMIC - Read only access for specified entry
 */
const void *raw_dynamic_rd_access(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		uint32_t size);

/*
 * RAW DYNAMIC - Write access for specified entry
 */
void *raw_dynamic_wr_access(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line,
		uint32_t size);

/*
 * RAW DYNAMIC - Flush specified entry
 */
int raw_dynamic_flush(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw, ocf_cache_line_t line);

/*
 * RAW DYNAMIC - Load all metadata of this RAW metadata container
 * from cache device
 */
int raw_dynamic_load_all(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAW DYNAMIC - Flush all metadata of this RAW metadata container
 * to cache device
 */
int raw_dynamic_flush_all(struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

/*
 * RAW DYNAMIC - Mark specified entry to be flushed
 */
void raw_dynamic_flush_mark(struct ocf_cache *cache, struct ocf_request *rq,
		uint32_t map_idx, int to_state, uint8_t start, uint8_t stop);

/*
 * DYNAMIC Implementation - Do Flush Asynchronously
 */
int raw_dynamic_flush_do_asynch(struct ocf_cache *cache, struct ocf_request *rq,
		struct ocf_metadata_raw *raw, ocf_req_end_t complete);


#endif /* METADATA_RAW_H_ */
