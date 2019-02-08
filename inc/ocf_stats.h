/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

/**
 * @file
 * @brief OCF API for getting and reseting statistics
 *
 * This file contains routines pertaining to retrieval and
 * manipulation of OCF IO statistics.
 */

#ifndef __OCF_STATS_H__
#define __OCF_STATS_H__

struct ocf_io;

/**
 * @brief OCF requests statistics like hit, miss, etc...
 *
 * @note To calculate number of hits request do:
 * total - (partial_miss + full_miss)
 */
struct ocf_stats_req {
	/** Number of partial misses */
	uint64_t partial_miss;

	/** Number of full misses */
	uint64_t full_miss;

	/** Total of requests */
	uint64_t total;

	/** Pass-through requests */
	uint64_t pass_through;
};

/**
 * @brief OCF error statistics
 */
struct ocf_stats_error {
	/** Read errors */
	uint32_t read;

	/** Write errors */
	uint32_t write;
};

/**
 * @brief OCF block statistics in bytes
 */
struct ocf_stats_block {
	/** Number of blocks read */
	uint64_t read;

	/** Number of blocks written */
	uint64_t write;
};

/**
 * Statistics appropriate for given IO class
 */
struct ocf_stats_io_class {
	/** Read requests statistics */
	struct ocf_stats_req read_reqs;

	/** Writes requests statistics */
	struct ocf_stats_req write_reqs;

	/** Block requests statistics */
	struct ocf_stats_block blocks;

	/** Number of cache lines available for given partition */
	uint64_t free_clines;

	/** Number of cache lines within lru list */
	uint64_t occupancy_clines;

	/** Number of dirty cache lines assigned to specific partition */
	uint64_t dirty_clines;
};

#define IO_PACKET_NO 12
#define IO_ALIGN_NO 4

/**
 * @brief Core debug statistics
 */
struct ocf_stats_core_debug {
	/** I/O sizes being read (grouped by packets) */
	uint64_t read_size[IO_PACKET_NO];

	/** I/O sizes being written (grouped by packets) */
	uint64_t write_size[IO_PACKET_NO];

	/** I/O alignment for reads */
	uint64_t read_align[IO_ALIGN_NO];

	/** I/O alignment for writes */
	uint64_t write_align[IO_ALIGN_NO];
};

/**
 * @brief OCF core statistics
 */
struct ocf_stats_core {
	/** Core size in cache line size unit */
	uint64_t core_size;

	/** Core size in bytes unit */
	uint64_t core_size_bytes;

	/** Number of cache lines allocated in the cache for this core */
	uint32_t cache_occupancy;

	/** Number of dirty cache lines allocated in the cache for this core */
	uint32_t dirty;

	/** Number of block flushed in ongoing flush operation */
	uint32_t flushed;

	/** How long core is dirty in seconds unit */
	uint32_t dirty_for;

	/** Read requests statistics */
	struct ocf_stats_req read_reqs;

	/** Write requests statistics */
	struct ocf_stats_req write_reqs;

	/** Block requests for cache volume statistics */
	struct ocf_stats_block cache_volume;

	/** Block requests for core volume statistics */
	struct ocf_stats_block core_volume;

	/** Block requests submitted by user to this core */
	struct ocf_stats_block core;

	/** Cache volume error statistics */
	struct ocf_stats_error cache_errors;

	/** Core volume error statistics */
	struct ocf_stats_error core_errors;

	/** Debug statistics */
	struct ocf_stats_core_debug debug_stat;

	/** Sequential cutoff threshold (in bytes) */
	uint32_t seq_cutoff_threshold;

	/** Sequential cutoff policy */
	ocf_seq_cutoff_policy seq_cutoff_policy;
};

/**
 * @brief Initialize or reset core statistics
 *
 * Initialize or reset counters used for statistics.
 *
 * @param[in] core Core handle
 */
void ocf_core_stats_initialize(ocf_core_t core);

/**
 * @brief Initialize or reset statistics of all cores in cache
 *
 * Initialize or reset counters used for statistics.
 *
 * @param[in] cache Cache handle
 */
void ocf_core_stats_initialize_all(ocf_cache_t cache);

/**
 * @brief ocf_core_io_class_get_stats retrieve io class statistics
 *			for given core
 *
 * Retrieve buffer of cache statistics for given cache instance.
 *
 * @param[in] core core handle to which request pertains
 * @param[in] part_id IO class, stats of which are requested
 * @param[out] stats statistic structure that shall be filled as
 *             a result of this function invocation.
 *
 * @result zero upon successful completion; error code otherwise
 */
int ocf_core_io_class_get_stats(ocf_core_t core, ocf_part_id_t part_id,
		struct ocf_stats_io_class *stats);

/**
 * @brief retrieve core stats
 *
 * Retrieve ocf per core stats (for all IO classes together)
 *
 * @param[in] core core ID to which request pertains
 * @param[out] stats statistics structure that shall be filled as
 *             a result of this function invocation.
 *
 * @result zero upon successful completion; error code otherwise
 */
int ocf_core_get_stats(ocf_core_t core, struct ocf_stats_core *stats);

/**
 * @brief update stats given IO request
 *
 * Function meant to update stats for IO request.
 *
 * @note This function shall be invoked for eac IO request processed
 *
 * @param[in] core to which request pertains
 * @param[in] io request for which stats are being updated
 */
void ocf_core_update_stats(ocf_core_t core, struct ocf_io *io);

#endif /* __OCF_STATS_H__ */
