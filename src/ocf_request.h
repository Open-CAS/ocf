/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_REQUEST_H__
#define __OCF_REQUEST_H__

#include "ocf_env.h"
#include "ocf_io_priv.h"
#include "engine/cache_engine.h"

struct ocf_req_allocator;

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

	uint32_t flush_metadata : 1;
	/*!< This bit tells if metadata flushing is required */

	uint32_t mapping_error : 1;
	/*!< Core lines in this request were not mapped into cache */

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
	ocf_cache_line_t hash;
	/*!< target LBA & core id hash */

	ocf_cache_line_t coll_idx;
	/*!< Index in collision table (in case of hit) */

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
	struct ocf_io_internal ioi;
	/*!< OCF IO associated with request */

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

	ocf_cache_t cache;
	/*!< Handle to cache instance */

	ocf_core_t core;
	/*!< Handle to core instance */

	const struct ocf_io_if *io_if;
	/*!< IO interface */

	void *priv;
	/*!< Filed for private data, context */

	void *master_io_req;
	/*!< Core device request context (core private info) */

	ctx_data_t *data;
	/*!< Request data*/

	ctx_data_t *cp_data;
	/*!< Copy of request data */

	ocf_req_cache_mode_t cache_mode;

	uint64_t byte_position;
	/*!< LBA byte position of request in core domain */

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

	int error;
	/*!< This filed indicates an error for OCF request */

	ocf_part_id_t part_id;
	/*!< Targeted partition of requests */

	uint8_t rw : 1;
	/*!< Indicator of IO direction - Read/Write */

	uint8_t d2c : 1;
	/**!< request affects metadata cachelines (is not direct-to-core) */

	uint8_t dirty : 1;
	/**!< indicates that request produces dirty data */

	uint8_t master_io_req_type : 2;
	/*!< Core device request context type */

	uint8_t seq_cutoff : 1;
	/*!< Sequential cut off set for this request */

	uint8_t wi_second_pass : 1;
	/*!< Set after first pass of WI write is completed */

	log_sid_t sid;
	/*!< Tracing sequence ID */

	uint64_t timestamp;
	/*!< Tracing timestamp */

	ocf_queue_t io_queue;
	/*!< I/O queue handle for which request should be submitted */

	struct list_head list;
	/*!< List item for OCF IO thread workers */

	struct ocf_req_info info;
	/*!< Detailed request info */

	void (*complete)(struct ocf_request *ocf_req, int error);
	/*!< Request completion function */

	struct ocf_req_discard_info discard;

	struct ocf_map_info *map;

	struct ocf_map_info __map[];
};

typedef void (*ocf_req_end_t)(struct ocf_request *req, int error);

/**
 * @brief Initialize OCF request allocation utility
 *
 * @param cache - OCF cache instance
 * @return Operation status 0 - successful, non-zero failure
 */
int ocf_req_allocator_init(struct ocf_ctx *ocf_ctx);

/**
 * @brief De-initialize OCF request allocation utility
 *
 * @param cache - OCF cache instance
 */
void ocf_req_allocator_deinit(struct ocf_ctx *ocf_ctx);

/**
 * @brief Allocate new OCF request
 *
 * @param queue - I/O queue handle
 * @param core - OCF core instance
 * @param addr - LBA of request
 * @param bytes - number of bytes of request
 * @param rw - Read or Write
 *
 * @return new OCF request
 */
struct ocf_request *ocf_req_new(ocf_queue_t queue, ocf_core_t core,
		uint64_t addr, uint32_t bytes, int rw);

/**
 * @brief Allocate OCF request map
 *
 * @param req OCF request
 *
 * @retval 0 Allocation succeed
 * @retval non-zero Allocation failed
 */
int ocf_req_alloc_map(struct ocf_request *req);

/**
 * @brief Allocate OCF request map for discard request
 *
 * @param req OCF request
 *
 * @retval 0 Allocation succeed
 * @retval non-zero Allocation failed
 */
int ocf_req_alloc_map_discard(struct ocf_request *req);

/**
 * @brief Allocate new OCF request with NOIO map allocation for huge request
 *
 * @param queue - I/O queue handle
 * @param core - OCF core instance
 * @param addr - LBA of request
 * @param bytes - number of bytes of request
 * @param rw - Read or Write
 *
 * @return new OCF request
 */

struct ocf_request *ocf_req_new_extended(ocf_queue_t queue, ocf_core_t core,
		uint64_t addr, uint32_t bytes, int rw);

/**
 * @brief Allocate new OCF request for DISCARD operation
 *
 * @param queue - I/O queue handle
 * @param core - OCF core instance
 * @param addr - LBA of request
 * @param bytes - number of bytes of request
 * @param rw - Read or Write
 *
 * @return new OCF request
 */
struct ocf_request *ocf_req_new_discard(ocf_queue_t queue, ocf_core_t core,
		uint64_t addr, uint32_t bytes, int rw);

/**
 * @brief Increment OCF request reference count
 *
 * @param req - OCF request
 */
void ocf_req_get(struct ocf_request *req);

/**
 * @brief Decrement OCF request reference. If reference is 0 then request will
 * be deallocated
 *
 * @param req - OCF request
 */
void ocf_req_put(struct ocf_request *req);

/**
 * @brief Clear OCF request info
 *
 * @param req - OCF request
 */
void ocf_req_clear_info(struct ocf_request *req);

/**
 * @brief Clear OCF request map
 *
 * @param req - OCF request
 */
void ocf_req_clear_map(struct ocf_request *req);

/**
 * @brief Calculate hashes for all core lines within the request
 *
 * @param req - OCF request
 */
void ocf_req_hash(struct ocf_request *req);

int ocf_req_set_dirty(struct ocf_request *req);

/**
 * @brief Clear OCF request
 *
 * @param req - OCF request
 */
static inline void ocf_req_clear(struct ocf_request *req)
{
	ocf_req_clear_info(req);
	ocf_req_clear_map(req);

	env_atomic_set(&req->lock_remaining, 0);
	env_atomic_set(&req->req_remaining, 0);
}

/**
 * @brief Return OCF request reference count
 *
 * @param req - OCF request
 * @return OCF request reference count
 */
static inline int ocf_req_ref_count(struct ocf_request *req)
{
	return env_atomic_read(&req->ref_count);
}

static inline bool ocf_req_is_4k(uint64_t addr, uint32_t bytes)
{
	return !((addr % PAGE_SIZE) || (bytes % PAGE_SIZE));
}

#endif /* __OCF_REQUEST_H__ */
