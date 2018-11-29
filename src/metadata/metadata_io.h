/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_IO_H__
#define __METADATA_IO_H__

/**
 * @file metadata_io.h
 * @brief Metadata IO utilities
 */

/**
 * @brief Metadata IO event
 *
 * The client of metadata IO service if informed trough this event:
 * - on completion of read from cache device
 * - on fill data which will be written into cache device
 *
 * @param data[in,out] Environment data for read ot write IO
 * @param page[in] Page which is issued
 * @param context[in] context caller
 *
 * @retval 0 Success
 * @retval Non-zero Error which will bee finally returned to the caller
 */
typedef int (*ocf_metadata_io_event_t)(struct ocf_cache *cache,
		ctx_data_t *data, uint32_t page, void *context);

/**
 * @brief Metadata write end callback
 *
 * @param cache - Cache instance
 * @param context - Read context
 * @param error - error
 * @param page - page that was written
 */
typedef void (*ocf_metadata_io_hndl_on_write_t)(struct ocf_cache *cache,
		void *context, int error);

struct metadata_io_request_asynch;

/*
 * IO request context
 */
struct metadata_io_request {
	struct ocf_cache *cache;
	void *context;
	uint32_t page;
	uint32_t count;
	ocf_metadata_io_event_t on_meta_fill;
	env_atomic req_remaining;
	ctx_data_t *data;
	env_completion completion;
	int error;
	struct metadata_io_request_asynch *asynch;
	env_atomic finished;

	struct ocf_request fl_req;
	struct list_head list;
};

/*
 * IO request context
 */
struct metadata_io_request_atomic {
	env_completion complete;
	int error;
};

/*
 *
 */
struct metadata_io {
	int error;
	int dir;
	struct ocf_cache *cache;
	uint32_t page;
	uint32_t count;
	env_completion completion;
	env_atomic rq_remaining;
	ocf_metadata_io_event_t hndl_fn;
	void *hndl_cntx;
};

/*
 * Asynchronous IO request context
 */
struct metadata_io_request_asynch {
	struct ocf_cache *cache;
	struct metadata_io_request *reqs;
	void *context;
	int error;
	size_t reqs_limit;
	env_atomic req_remaining;
	env_atomic req_active;
	uint32_t page;
	ocf_metadata_io_hndl_on_write_t on_complete;
};

/**
 * @brief Metadata read end callback
 *
 * @param cache Cache instance
 * @param sector_addr Begin sector of metadata
 * @param sector_no Number of sectors
 * @param data Data environment buffer with atomic metadata
 *
 * @retval 0 Success
 * @retval Non-zero Error which will bee finally returned to the caller
 */
typedef int (*ocf_metadata_atomic_io_event_t)(
		struct ocf_cache *cache, uint64_t sector_addr,
		uint32_t sector_no, ctx_data_t *data);

/**
 * @brief Write page request
 *
 * @param cache - Cache instance
 * @param data - Data to be written for specified page
 * @param page - Page of SSD (cache device) where data has to be placed
 * @return 0 - No errors, otherwise error occurred
 */
int metadata_io_write(struct ocf_cache *cache,
		void *data, uint32_t page);

int metadata_io_read_i_atomic(struct ocf_cache *cache,
		ocf_metadata_atomic_io_event_t hndl);

/**
 * @brief Iterative pages write
 *
 * @param cache - Cache instance
 * @param page - Start page of SSD (cache device) where data will be written
 * @param count - Counts of page to be processed
 * @param hndl_fn - Fill callback is called to fill each pages with data
 * @param hndl_cntx - Caller context which is passed on fill callback request
 *
 * @return 0 - No errors, otherwise error occurred
 */
int metadata_io_write_i(struct ocf_cache *cache,
		uint32_t page, uint32_t count,
		ocf_metadata_io_event_t hndl_fn, void *hndl_cntx);

/**
 * * @brief Iterative pages read
 *
 * @param cache - Cache instance
 * @param page - Start page of SSD (cache device) of data will be read
 * @param count - Counts of page to be processed
 * @param hndl_fn - Callback function is called on each page read completion
 * @param hndl_cntx - Caller context passed during handle function call
 *
 * @return 0 - No errors, otherwise error occurred
 */
int metadata_io_read_i(struct ocf_cache *cache,
		uint32_t page, uint32_t count,
		ocf_metadata_io_event_t hndl_fn, void *hndl_cntx);

/**
 * @brief Iterative asynchronous pages write
 *
 * @param cache - Cache instance
 * @param context - Read context
 * @param page - Start page of SSD (cache device) where data will be written
 * @param count - Counts of page to be processed
 * @param fill - Fill callback
 * @param complete - All IOs completed callback
 *
 * @return 0 - No errors, otherwise error occurred
 */
int metadata_io_write_i_asynch(struct ocf_cache *cache, uint32_t queue,
		void *context, uint32_t page, uint32_t count,
		ocf_metadata_io_event_t fill_hndl,
		ocf_metadata_io_hndl_on_write_t compl_hndl);

/**
 * Function for initializing metadata io.
 */
int ocf_metadata_io_init(ocf_cache_t cache);

/**
 * Function for deinitializing metadata io.
 */
void ocf_metadata_io_deinit(ocf_cache_t cache);

#endif /* METADATA_IO_UTILS_H_ */
