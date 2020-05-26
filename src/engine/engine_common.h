/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef ENGINE_COMMON_H_
#define ENGINE_COMMON_H_

#include "../ocf_request.h"
#include "../utils/utils_cache_line.h"

/**
 * @file engine_common.h
 * @brief OCF cache engine common module
 */

/**
 * @brief Signal and handle OCF request error
 *
 * @param req OCF request
 * @param stop_cache Indicates if OCF cache engine need to be stopped
 * @param msg Error message to be printed into log
 */
void ocf_engine_error(struct ocf_request *req, bool stop_cache,
		const char *msg);

/**
 * @brief Check if OCF request is hit
 *
 * @param req OCF request
 *
 * @retval true HIT
 * @retval false MISS
 */
static inline bool ocf_engine_is_hit(struct ocf_request *req)
{
	return req->info.hit_no == req->core_line_count;
}

/**
 * @brief Check if OCF request is miss
 *
 * @param req OCF request
 *
 * @retval true MISS
 * @retval false HIT
 */
#define ocf_engine_is_miss(req) (!ocf_engine_is_hit(req))

/**
 * @brief Check if all cache lines are mapped fully
 *
 * @param req OCF request
 *
 * @retval true request is mapped fully
 * @retval false request is not mapped fully and eviction might be run in
 * order to complete mapping
 */
static inline bool ocf_engine_is_mapped(struct ocf_request *req)
{
	return req->info.hit_no + req->info.invalid_no == req->core_line_count;
}

/**
 * @brief Check if all cache lines are dirty
 *
 * @param req OCF request
 *
 * @retval true request is dirty fully
 * @retval false request is not dirty fully
 */
static inline bool ocf_engine_is_dirty_all(struct ocf_request *req)
{
	return req->info.dirty_all == req->core_line_count;
}

/**
 * @brief Get number of mapped cache lines
 *
 * @param req OCF request
 *
 * @return Number of mapped cache lines
 */
static inline uint32_t ocf_engine_mapped_count(struct ocf_request *req)
{
	return req->info.hit_no + req->info.invalid_no;
}

/**
 * @brief Get number of unmapped cache lines
 *
 * @param req OCF request
 *
 * @return Number of unmapped cache lines
 */
static inline uint32_t ocf_engine_unmapped_count(struct ocf_request *req)
{
	return req->core_line_count - (req->info.hit_no + req->info.invalid_no);
}

/**
 * @brief Get number of IOs to perform cache read or write
 *
 * @param req OCF request
 *
 * @return Count of cache IOs
 */
static inline uint32_t ocf_engine_io_count(struct ocf_request *req)
{
	return req->info.seq_req ? 1 : req->core_line_count;
}

static inline
bool ocf_engine_map_all_sec_dirty(struct ocf_request *req, uint32_t line)
{
	uint8_t start = ocf_map_line_start_sector(req, line);
	uint8_t end = ocf_map_line_end_sector(req, line);

	if (req->map[line].status != LOOKUP_HIT)
		return false;

	return metadata_test_dirty_all_sec(req->cache, req->map[line].coll_idx,
		start, end);
}

static inline
bool ocf_engine_map_all_sec_clean(struct ocf_request *req, uint32_t line)
{
	uint8_t start = ocf_map_line_start_sector(req, line);
	uint8_t end = ocf_map_line_end_sector(req, line);

	if (req->map[line].status != LOOKUP_HIT)
		return false;

	if (!metadata_test_valid_sec(req->cache, req->map[line].coll_idx,
			start, end)) {
		return false;
	}

	return !metadata_test_dirty_sec(req->cache, req->map[line].coll_idx,
			start, end);
}

static inline
bool ocf_engine_map_all_sec_valid(struct ocf_request *req, uint32_t line)
{
	uint8_t start = ocf_map_line_start_sector(req, line);
	uint8_t end = ocf_map_line_end_sector(req, line);

	if (req->map[line].status != LOOKUP_HIT)
		return false;

	return metadata_test_valid_sec(req->cache, req->map[line].coll_idx,
			start, end);
}

/**
 * @brief Clean request (flush dirty data to the core device)
 *
 * @param req OCF request
 *
 * @note After successful cleaning:
 *	- Dirty status bits in request info will be cleared
 *	- Request will be pushed front, <B>IO interface need to be set</B>
 *
 * @note In case of failure:
 *	- unlock request
 *	- complete request to the application
 *	- free request
 */
void ocf_engine_clean(struct ocf_request *req);

void ocf_engine_lookup_map_entry(struct ocf_cache *cache,
		struct ocf_map_info *entry, ocf_core_id_t core_id,
		uint64_t core_line);

/**
 * @brief Request cacheline lock type
 */
enum ocf_engine_lock_type
{
	/** No lock */
	ocf_engine_lock_none = 0,
	/** Write lock */
	ocf_engine_lock_write,
	/** Read lock */
	ocf_engine_lock_read,
};

/**
 * @brief Engine-specific callbacks for common request handling rountine
 *
 * TODO(arutk): expand this structure to fit all engines and all steps
 */
struct ocf_engine_callbacks
{
	/** Specify locking requirements after request is mapped */
	enum ocf_engine_lock_type (*get_lock_type)(struct ocf_request *req);

	/** Resume handling after acquiring asynchronous lock */
	ocf_req_async_lock_cb resume;
};

/**
 * @brief Map and lock cachelines
 *
 * @param req OCF request
 *
 * @returns eviction status
 * @retval LOOKUP_MAPPED successfully evicted required number of cachelines
 * @retval LOOKUP_MISS eviction failure
 */
int ocf_engine_prepare_clines(struct ocf_request *req,
		const struct ocf_engine_callbacks *engine_cbs);

/**
 * @brief Traverse OCF request (lookup cache)
 *
 * @note This function does not evict cachelines. Only lookup in metadata is
 * performed. Main purpose of this function is to check if there is a HIT.
 *
 * @param req OCF request
 */
void ocf_engine_traverse(struct ocf_request *req);

/**
 * @brief Check if OCF request mapping is still valid
 *
 * @note If mapping entries is invalid it will be marked
 *
 * @param req OCF request
 *
 * @retval 0 - OCF request mapping is valid
 * @return Non zero - OCF request mapping is invalid and need to call re-mapping
 */
int ocf_engine_check(struct ocf_request *req);

/**
 * @brief Update OCF request info
 *
 * @param req OCF request
 */
void ocf_engine_update_req_info(struct ocf_cache *cache,
		struct ocf_request *req, uint32_t entry);

/**
 * @brief Update OCF request block statistics for an exported object
 *
 * @param req OCF request
 */
void ocf_engine_update_block_stats(struct ocf_request *req);

/**
 * @brief Update OCF request request statistics for an exported object
 * (not applicable to write wi and to read wt
 *
 * @param req OCF request
 */
void ocf_engine_update_request_stats(struct ocf_request *req);

/**
 * @brief Push front OCF request to the OCF thread worker queue
 *
 * @param req OCF request
 * @param allow_sync caller allows for request from queue to be ran immediately
		from push function in caller context
 */
void ocf_engine_push_req_back(struct ocf_request *req,
		bool allow_sync);

/**
 * @brief Push back OCF request to the OCF thread worker queue
 *
 * @param req OCF request
 * @param allow_sync caller allows for request from queue to be ran immediately
		from push function in caller context
 */
void ocf_engine_push_req_front(struct ocf_request *req,
		bool allow_sync);

/**
 * @brief Set interface and push from request to the OCF thread worker queue
 *
 * @param req OCF request
 * @param io_if IO interface
 * @param allow_sync caller allows for request from queue to be ran immediately
		from push function in caller context
 */
void ocf_engine_push_req_front_if(struct ocf_request *req,
		const struct ocf_io_if *io_if,
		bool allow_sync);

void inc_fallback_pt_error_counter(ocf_cache_t cache);

void ocf_engine_on_resume(struct ocf_request *req);

#endif /* ENGINE_COMMON_H_ */
