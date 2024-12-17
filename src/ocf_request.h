/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_REQUEST_H__
#define __OCF_REQUEST_H__

#include "ocf_env.h"
#include "ocf_io_priv.h"
#include "ocf_def_priv.h"
#include "metadata/metadata_structs.h"

typedef enum {
	/* modes inherited from user API */
	ocf_req_cache_mode_wt = ocf_cache_mode_wt,
	ocf_req_cache_mode_wb = ocf_cache_mode_wb,
	ocf_req_cache_mode_wa = ocf_cache_mode_wa,
	ocf_req_cache_mode_pt = ocf_cache_mode_pt,
	ocf_req_cache_mode_wi = ocf_cache_mode_wi,
	ocf_req_cache_mode_wo = ocf_cache_mode_wo,

	/* internal modes */
	ocf_req_cache_mode_fast,
		/*!< Fast path */
	ocf_req_cache_mode_d2c,
		/*!< Direct to Core - pass through to core without
				touching cacheline metadata */

	ocf_req_cache_mode_max,
} ocf_req_cache_mode_t;

struct ocf_req_allocator;

struct ocf_req_info {
	/* Number of hits, invalid, misses, reparts. */
	unsigned int hit_no;
	unsigned int invalid_no;
	unsigned int re_part_no;
	unsigned int seq_no;
	unsigned int insert_no;

	uint32_t dirty_all;
	/*!< Number of dirty line in request*/

	uint32_t dirty_any;
	/*!< Indicates that at least one request is dirty */

	uint32_t flush_metadata : 1;
	/*!< This bit tells if metadata flushing is required */

	uint32_t mapping_error : 1;
	/*!< Core lines in this request were not mapped into cache */

	uint32_t cleaning_required : 1;
	/*!< Eviction failed, need to request cleaning */

	uint32_t cache_error : 1;
	/*!< Error occurred during I/O on cache device */

	uint32_t core_error : 1;
	/*!< Error occurred during I/O on core device */

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
 * @brief OCF IO engine handler callback
 */
struct ocf_request;
typedef int (*ocf_req_cb)(struct ocf_request *req);

struct ocf_request_io {

	/**
	 * @brief OCF IO destination class
	 */
	uint8_t io_class;

	/**
	 * @brief Front volume handle
	 */
	ocf_volume_t volume;

	/**
	 * @brief OCF IO start function
	 */
	ocf_start_io_t start;

	/**
	 * @brief OCF IO private 1
	 */
	void *priv1;

	/**
	 * @brief OCF IO private 2
	 */
	void *priv2;

	/**
	 * @brief OCF IO handle function
	 */
	ocf_handle_io_t handle;

	/**
	 * @brief OCF IO completion function
	 */
	ocf_end_io_t end;
};

/**
 * @brief OCF IO request
 */
struct ocf_request {
	/* This struct is temporary. It will be consolidated with ocf_request */
	struct ocf_request_io io;

	ocf_req_end_t cache_forward_end;
	ocf_req_end_t core_forward_end;
	env_atomic cache_remaining;
	env_atomic core_remaining;

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

	const struct ocf_engine_callbacks *engine_cbs;
	/*!< Engine owning the request */

	ocf_cache_t cache;
	/*!< Handle to cache instance */

	ocf_core_t core;
	/*!< Handle to core instance */

	ocf_req_cb engine_handler;
	/*!< IO engine handler */

	void *priv;
	/*!< Filed for private data, context */

	void *master_io_req;
	/*!< Core device request context (core private info) */

	ctx_data_t *data;
	/*!< Request data*/

	ctx_data_t *cp_data;
	/*!< Copy of request data */

	uint64_t core_line_first;
	/*! First core line */

	uint64_t core_line_last;
	/*! Last core line */

	uint32_t core_line_count;
	/*! Core line count */

	uint32_t alloc_core_line_count;
	/*! Number of core lines at time of request allocation */

	uint64_t addr;
	/*!< LBA byte position of request in core domain */

	uint32_t bytes;
	/*!< Byte length of OCF request */

	uint32_t offset;
	/*!< Offset into request data*/

	uint64_t flags;
	/*!< IO flags */

	int error;
	/*!< This filed indicates an error for OCF request */

	int cache_error;
	/*!< Indicator of forward IO cache device error */

	int core_error;
	/*!< Indicator of forward IO core device error */

	ocf_part_id_t part_id;
	/*!< Targeted partition of requests */

	uint8_t rw : 1;
	/*!< Indicator of IO direction - Read/Write */

	uint32_t alock_rw: 1;
	/*!< Read/Write mode for alock*/

	uint8_t d2c : 1;
	/**!< request affects metadata cachelines (is not direct-to-core) */

	uint8_t cleaner : 1;
	/**!< request allocated by cleaner */

	uint8_t dirty : 1;
	/**!< indicates that request produces dirty data */

	uint8_t master_io_req_type : 2;
	/*!< Core device request context type */

	uint8_t seq_cutoff_core : 1;
	/*!< Sequential cut off stream promoted to core level */

	uint8_t seq_cutoff : 1;
	/*!< Sequential cut off set for this request */

	uint8_t force_pt : 1;
	/*!< Force pass-thru cache mode */

	uint8_t wi_second_pass : 1;
	/*!< Set after first pass of WI write is completed */

	uint8_t part_evict : 1;
	/* !< Some cachelines from request's partition must be evicted */

	uint8_t complete_queue : 1;
	/* !< Request needs to be completed from the queue context */

	uint8_t lock_idx : OCF_METADATA_GLOBAL_LOCK_IDX_BITS;
	/* !< Selected global metadata read lock */

	uint8_t is_deferred : 1;
	/* !< request handling was deferred and eventually resumed */

	uint8_t is_mngt : 1;
	/* !< It's a management path request */

	ocf_req_cache_mode_t cache_mode;

	ocf_queue_t io_queue;
	/*!< I/O queue handle for which request should be submitted */

	struct list_head list;
	/*!< List item for OCF IO thread workers */

	struct ocf_req_info info;
	/*!< Detailed request info */

	ocf_req_end_t complete;
	/*!< Request completion function */

	struct ocf_req_discard_info discard;

	uint8_t *alock_status;
	/*!< Mapping for locked/unlocked alock entries */

	struct ocf_map_info *map;

	struct ocf_map_info __map[0];
};

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
 * @brief Allocate new OCF request for the management path
 *
 * @param queue - I/O queue handle
 *
 * @return new OCF request
 */
struct ocf_request *ocf_req_new_mngt(ocf_cache_t cache, ocf_queue_t queue);

/**
 * @brief Allocate new OCF request for cleaner
 *
 * @param queue - I/O queue handle
 * @param count - Number of map entries
 *
 * @return new OCF request
 */
struct ocf_request *ocf_req_new_cleaner(ocf_cache_t cache, ocf_queue_t queue,
		uint32_t count);

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
 * @brief Allocate new OCF request for cache IO
 *
 * @param cache - OCF cache instance
 * @param queue - I/O queue handle
 * @param addr - LBA of request
 * @param bytes - number of bytes of request
 * @param rw - Read or Write
 *
 * @return new OCF request
 */
struct ocf_request *ocf_req_new_cache(ocf_cache_t cache, ocf_queue_t queue,
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

/**
 * @brief Request should trigger eviction from it's target partition
 *
 * @param req - OCF request
 */
static inline void ocf_req_set_part_evict(struct ocf_request *req)
{
	req->part_evict = true;
}

/**
 * @brief Request shouldn't trigger eviction from it's target partition
 *
 * @param req - OCF request
 */
static inline void ocf_req_clear_part_evict(struct ocf_request *req)
{
	req->part_evict = false;
}

/**
 * @brief Check wheter request shouldn't trigger eviction from it's target
 *  partition or any partition
 *
 * @param req - OCF request
 * @return true - Eviciton should be triggered from request's target partition
 * @return false - Eviction should be triggered with respect to eviction
 * priority
 */
static inline bool ocf_req_part_evict(struct ocf_request *req)
{
	return req->part_evict;
}

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

static inline void ocf_req_set_mapping_error(struct ocf_request *req)
{
	req->info.mapping_error = true;
}

static inline bool ocf_req_test_mapping_error(struct ocf_request *req)
{
	return req->info.mapping_error;
}

static inline void ocf_req_set_cleaning_required(struct ocf_request *req)
{
	req->info.cleaning_required = true;
}

static inline bool ocf_req_is_cleaning_required(struct ocf_request *req)
{
	return req->info.cleaning_required;
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

static inline void ocf_req_forward_cache_get(struct ocf_request *req)
{
	env_atomic_inc(&req->cache_remaining);
}

static inline void ocf_req_forward_cache_put(struct ocf_request *req)
{
	if (env_atomic_dec_return(&req->cache_remaining) == 0)
		req->cache_forward_end(req, req->cache_error);
}

static inline void ocf_req_forward_core_get(struct ocf_request *req)
{
	env_atomic_inc(&req->core_remaining);
}

static inline void ocf_req_forward_core_put(struct ocf_request *req)
{
	if (env_atomic_dec_return(&req->core_remaining) == 0)
		req->core_forward_end(req, req->core_error);
}

static inline ocf_forward_token_t ocf_req_to_cache_forward_token(struct ocf_request *req)
{
	return (ocf_forward_token_t)req | 1;
}

static inline ocf_forward_token_t ocf_req_to_core_forward_token(struct ocf_request *req)
{
	return (ocf_forward_token_t)req;
}

static inline struct ocf_request *ocf_req_forward_token_to_req(ocf_forward_token_t token)
{
	return (struct ocf_request *)(token & ~1);
}

void ocf_req_forward_volume_init(struct ocf_request *req,
		ocf_req_end_t callback);

void ocf_req_forward_volume_io(struct ocf_request *req, ocf_volume_t volume,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset);

void ocf_req_forward_volume_flush(struct ocf_request *req, ocf_volume_t volume);

void ocf_req_forward_volume_discard(struct ocf_request *req,
		ocf_volume_t volume, uint64_t addr, uint64_t bytes);

void ocf_req_forward_volume_io_simple(struct ocf_request *req,
		ocf_volume_t volume, int dir, uint64_t addr, uint64_t bytes);

void ocf_req_forward_cache_init(struct ocf_request *req,
		ocf_req_end_t callback);

void ocf_req_forward_cache_io(struct ocf_request *req, int dir, uint64_t addr,
		uint64_t bytes, uint64_t offset);

void ocf_req_forward_cache_flush(struct ocf_request *req);

void ocf_req_forward_cache_discard(struct ocf_request *req, uint64_t addr,
		uint64_t bytes);

void ocf_req_forward_cache_write_zeros(struct ocf_request *req, uint64_t addr,
		uint64_t bytes);

void ocf_req_forward_cache_metadata(struct ocf_request *req, int dir,
		uint64_t addr, uint64_t bytes, uint64_t offset);

void ocf_req_forward_core_init(struct ocf_request *req,
		ocf_req_end_t callback);

void ocf_req_forward_core_io(struct ocf_request *req, int dir, uint64_t addr,
		uint64_t bytes, uint64_t offset);

void ocf_req_forward_core_flush(struct ocf_request *req);

void ocf_req_forward_core_discard(struct ocf_request *req, uint64_t addr,
		uint64_t bytes);

#endif /* __OCF_REQUEST_H__ */
