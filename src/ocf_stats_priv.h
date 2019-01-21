/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_STATS_PRIV_H__
#define __OCF_STATS_PRIV_H__

struct ocf_counters_block {
	env_atomic64 read_bytes;
	env_atomic64 write_bytes;
};

struct ocf_counters_error {
	env_atomic read;
	env_atomic write;
};

struct ocf_counters_req {
	env_atomic64 partial_miss;
	env_atomic64 full_miss;
	env_atomic64 total;
	env_atomic64 pass_through;
};

/**
 * statistics appropriate for given io class.
 */
struct ocf_counters_part {
	struct ocf_counters_req read_reqs;
	struct ocf_counters_req write_reqs;

	struct ocf_counters_block blocks;
};

#ifdef OCF_DEBUG_STATS
struct ocf_counters_debug {
	env_atomic64 write_size[IO_PACKET_NO];
	env_atomic64 read_size[IO_PACKET_NO];

	env_atomic64 read_align[IO_ALIGN_NO];
	env_atomic64 write_align[IO_ALIGN_NO];
};
#endif

struct ocf_counters_core {
	struct ocf_counters_block core_blocks;
	struct ocf_counters_block cache_blocks;

	struct ocf_counters_error core_errors;
	struct ocf_counters_error cache_errors;

	struct ocf_counters_part part_counters[OCF_IO_CLASS_MAX];
#ifdef OCF_DEBUG_STATS
	struct ocf_counters_debug debug_stats;
#endif
};

#endif
