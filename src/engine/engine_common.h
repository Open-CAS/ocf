/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef ENGINE_COMMON_H_
#define ENGINE_COMMON_H_

#include "../ocf_request.h"

/**
 * @file engine_common.h
 * @brief OCF cache engine common module
 */

/**
 * @brief Signal and handle OCF request error
 *
 * @param rq OCF request
 * @param stop_cache Indicates if OCF cache engine need to be stopped
 * @param msg Error message to be printed into log
 */
void ocf_engine_error(struct ocf_request *rq, bool stop_cache,
		const char *msg);

/**
 * @brief Check if OCF request is hit
 *
 * @param rq OCF request
 *
 * @retval true HIT
 * @retval false MISS
 */
static inline bool ocf_engine_is_hit(struct ocf_request *rq)
{
	return rq->info.hit_no == rq->core_line_count;
}

/**
 * @brief Check if OCF request is miss
 *
 * @param rq OCF request
 *
 * @retval true MISS
 * @retval false HIT
 */
#define ocf_engine_is_miss(rq) (!ocf_engine_is_hit(rq))

/**
 * @brief Check if all cache lines are mapped fully
 *
 * @param rq OCF request
 *
 * @retval true request is mapped fully
 * @retval false request is not mapped fully and eviction might be run in
 * order to complete mapping
 */
static inline bool ocf_engine_is_mapped(struct ocf_request *rq)
{
	return rq->info.hit_no + rq->info.invalid_no == rq->core_line_count;
}

/**
 * @brief Check if all cache lines are dirty
 *
 * @param rq OCF request
 *
 * @retval true request is dirty fully
 * @retval false request is not dirty fully
 */
static inline bool ocf_engine_is_dirty_all(struct ocf_request *rq)
{
	return rq->info.dirty_all == rq->core_line_count;
}

/**
 * @brief Get number of mapped cache lines
 *
 * @param rq OCF request
 *
 * @return Number of mapped cache lines
 */
static inline uint32_t ocf_engine_mapped_count(struct ocf_request *rq)
{
	return rq->info.hit_no + rq->info.invalid_no;
}

/**
 * @brief Get number of unmapped cache lines
 *
 * @param rq OCF request
 *
 * @return Number of unmapped cache lines
 */
static inline uint32_t ocf_engine_unmapped_count(struct ocf_request *rq)
{
	return rq->core_line_count - (rq->info.hit_no + rq->info.invalid_no);
}

/**
 * @brief Get number of IOs to perform cache read or write
 *
 * @param rq OCF request
 *
 * @return Count of cache IOs
 */
static inline uint32_t ocf_engine_io_count(struct ocf_request *rq)
{
	return rq->info.seq_req ? 1 : rq->core_line_count;
}

/**
 * @brief Clean request (flush dirty data to the core device)
 *
 * @param rq OCF request
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
void ocf_engine_clean(struct ocf_request *rq);

void ocf_engine_lookup_map_entry(struct ocf_cache *cache,
		struct ocf_map_info *entry, ocf_core_id_t core_id,
		uint64_t core_line);

/**
 * @brief Traverse request in order to lookup cache lines If there are misses
 * need to call eviction. This process is called 'mapping'.
 *
 * @note This function CALL EVICTION
 *
 * @param rq OCF request
 */
void ocf_engine_map(struct ocf_request *rq);

/**
 * @brief Traverse OCF request (lookup cache)
 *
 * @note This function DO NOT CALL EVICTION. Only lookup in metadata is
 * performed. Main purpose of this function is to check if there is a HIT.
 *
 * @param rq OCF request
 */
void ocf_engine_traverse(struct ocf_request *rq);

/**
 * @brief Check if OCF request mapping is still valid
 *
 * @note If mapping entries is invalid it will be marked
 *
 * @param rq OCF request
 *
 * @retval 0 - OCF request mapping is valid
 * @return Non zero - OCF request mapping is invalid and need to call re-mapping
 */
int ocf_engine_check(struct ocf_request *rq);

/**
 * @brief Update OCF request info
 *
 * @param rq OCF request
 */
void ocf_engine_update_rq_info(struct ocf_cache *cache,
		struct ocf_request *rq, uint32_t entry);

/**
 * @brief Update OCF request block statistics for an exported object
 *
 * @param rq OCF request
 */
void ocf_engine_update_block_stats(struct ocf_request *rq);

/**
 * @brief Update OCF request request statistics for an exported object
 * (not applicable to write wi and to read wt
 *
 * @param rq OCF request
 */
void ocf_engine_update_request_stats(struct ocf_request *rq);

/**
 * @brief Push front OCF request to the OCF thread worker queue
 *
 * @param rq OCF request
 * @param allow_sync caller allows for request from queue to be ran immediately
		from push function in caller context
 */
void ocf_engine_push_rq_back(struct ocf_request *rq,
		bool allow_sync);

/**
 * @brief Push back OCF request to the OCF thread worker queue
 *
 * @param rq OCF request
 * @param allow_sync caller allows for request from queue to be ran immediately
		from push function in caller context
 */
void ocf_engine_push_rq_front(struct ocf_request *rq,
		bool allow_sync);

/**
 * @brief Set interface and push from request to the OCF thread worker queue
 *
 * @param rq OCF request
 * @param io_if IO interface
 * @param allow_sync caller allows for request from queue to be ran immediately
		from push function in caller context
 */
void ocf_engine_push_rq_front_if(struct ocf_request *rq,
		const struct ocf_io_if *io_if,
		bool allow_sync);

void inc_fallback_pt_error_counter(ocf_cache_t cache);

void ocf_engine_on_resume(struct ocf_request *rq);

#endif /* ENGINE_COMMON_H_ */
