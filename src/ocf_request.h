/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_REQUEST_H__
#define __OCF_REQUEST_H__

#include "ocf_env.h"

struct ocf_req_info {
	/* Number of hits, invalid, misses. */
	unsigned int hit_no;
	unsigned int invalid_no;

	uint32_t dirty_all;
	/*!< Number of dirty line in request*/

	uint32_t dirty_any;
	/*!< Indicates that at least one request is dirty */

	uint32_t seq_req : 1;
	/*!< Sequential cache request flag. */

	uint32_t seq_cutoff : 1;
	/*!< Sequential cut off set for this request */

	uint32_t flush_metadata : 1;
	/*!< This bit tells if metadata flushing is required */

	uint32_t eviction_error : 1;
	/*!< Eviction error flag */

	uint32_t re_part : 1;
	/*!< This bit indicate that in the request some cache lines
	 * has to be moved to another partition
	 */

	uint32_t core_error : 1;
	/*!< Error occured during I/O on core device */

	uint32_t cleaner_cache_line_lock : 1;
	/*!< Cleaner flag - acquire cache line lock */

	uint32_t internal : 1;
	/**!< this is an internal request */
};

struct ocf_map_info {
	/* If HIT -> pointer to hash_key and coll_idx */
	unsigned int hash_key;
	unsigned int coll_idx;

	uint64_t core_line;

	ocf_core_id_t core_id;
	/*!< Core id for multi-core requests */

	uint16_t status : 8;
	/*!< Traverse or mapping status - HIT, MISS, etc... */

	uint16_t rd_locked : 1;
	/*!< Indicates if cache line is locked for READ access */

	uint16_t wr_locked : 1;
	/*!< Indicates if cache line is locked for WRITE access */

	uint16_t invalid : 1;
	/*!< This bit indicates that mapping is invalid */

	uint16_t re_part : 1;
	/*!< This bit indicates if cache line need to be moved to the
	 * new partition
	 */

	uint16_t flush : 1;
	/*!< This bit indicates if cache line need to be flushed */

	uint8_t start_flush;
	/*!< If req need flush, contain first sector of range to flush */

	uint8_t stop_flush;
	/*!< If req need flush, contain last sector of range to flush */
};

/**
 * @brief OCF discard request info
 */
struct ocf_req_discard_info {
	sector_t sector;
		/*!< The start sector for discard request */

	sector_t nr_sects;
		/*!< Number of sectors to be discarded */

	sector_t handled;
		/*!< Number of processed sector during discard operation */
};

/**
 * @brief OCF IO request
 */
struct ocf_request {
	env_atomic ref_count;
	/*!< Reference usage count, once OCF request reaches zero it
	 * will be de-initialed. Get/Put method are intended to modify
	 * reference counter
	 */

	env_atomic lock_remaining;
	/*!< This filed indicates how many cache lines in the request
	 * map left to be locked
	 */

	env_atomic req_remaining;
	/*!< In case of IO this field indicates how many IO left to
	 * accomplish IO
	 */

	env_atomic master_remaining;
	/*!< Atomic counter for core device */

	struct ocf_cache *cache;
	/*!< Handle to cache instance */

	const struct ocf_io_if *io_if;
	/*!< IO interface */

	void (*resume)(struct ocf_request *req);
	/*!< OCF request resume callback */

	ocf_core_id_t core_id;
	/*!< This file indicates core id of request */

	ocf_part_id_t part_id;
	/*!< Targeted partition of requests */

	void *priv;
	/*!< Filed for private data, context */

	void *master_io_req;
	/*!< Core device request context (core private info) */

	ctx_data_t *data;
	/*!< Request data*/

	ctx_data_t *cp_data;
	/*!< Copy of request data */

	uint64_t byte_position;
	/*!< LBA byte position of request in code domain */

	uint64_t core_line_first;
	/*! First core line */

	uint64_t core_line_last;
	/*! Last core line */

	uint32_t byte_length;
	/*!< Byte length of OCF reuqest */

	uint32_t core_line_count;
	/*! Core line count */

	uint32_t alloc_core_line_count;
	/*! Core line count for which request was initially allocated */

	uint32_t io_queue;
	/*!< I/O queue id for which request should be submitted */

	int error;
	/*!< This filed indicates an error for OCF request */

	int rw;
	/*!< Indicator of IO direction - Read/Write */

	struct list_head list;
	/*!< List item for OCF IO thread workers */

	struct ocf_req_info info;
	/*!< Detailed request info */

	uint8_t d2c;
	/**!< request affects metadata cachelines (is not direct-to-core) */

	uint8_t master_io_req_type;
	/*!< Core device request context type */

	void (*complete)(struct ocf_request *ocf_req, int error);
	/*!< Request completion funstion */

	struct ocf_io *io;
	/*!< OCF IO associated with request */

	struct ocf_req_discard_info discard;

	struct ocf_map_info *map;

	struct ocf_map_info __map[];
};

typedef void (*ocf_req_end_t)(struct ocf_request *req, int error);

#endif
