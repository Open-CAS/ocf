/*
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PREFETCH_READAHEAD_H__
#define __OCF_PREFETCH_READAHEAD_H__

/**
 * @file
 * @brief Readahead prefetch policy API
 */

enum ocf_prefetch_readahead_parameters {
	ocf_readahead_threshold,
};

/**
 * @name Readahead prefetch policy parameters
 * @{
 */

/**
 * Readahead threshold - minimum sequential stream bytes before prefetching
 */

/** Threshold minimum value (bytes) */
#define OCF_PF_READAHEAD_MIN_THRESHOLD		0
/** Threshold maximum value (bytes) */
#define OCF_PF_READAHEAD_MAX_THRESHOLD		4294967295U
/** Threshold default value (bytes) */
#define OCF_PF_READAHEAD_DEFAULT_THRESHOLD		(64 * KiB)

/**
 * @}
 */

#endif /* __OCF_PREFETCH_READAHEAD_H__ */
