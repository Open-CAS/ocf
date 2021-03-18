/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_PARTITION_STRUCTS_H__
#define __METADATA_PARTITION_STRUCTS_H__

#include "../utils/utils_list.h"
#include "../cleaning/cleaning.h"
#include "../eviction/eviction.h"

struct ocf_user_part_config {
	char name[OCF_IO_CLASS_NAME_MAX];
	uint32_t min_size;
	uint32_t max_size;
	int16_t priority;
	ocf_cache_mode_t cache_mode;
	struct {
		uint8_t valid : 1;
		uint8_t added : 1;
		uint8_t eviction : 1;
			/*!< This bits is setting during partition sorting,
			* and means that can evict from this partition
			*/
	} flags;
};

struct ocf_user_part_runtime {
	uint32_t curr_size;
	uint32_t head;
	struct eviction_policy eviction[OCF_NUM_EVICTION_LISTS];
	struct cleaning_policy cleaning;
};

typedef bool ( *_lru_hash_locked_pfn)(struct ocf_request *req,
		ocf_core_id_t core_id, uint64_t core_line);

/* Iterator state, visiting all eviction lists within a partition
   in round robin order */
struct ocf_lru_iter
{
	/* cache object */
	ocf_cache_t cache;
	/* target partition */
	struct ocf_user_part *part;
	/* per-partition cacheline iterator */
	ocf_cache_line_t curr_cline[OCF_NUM_EVICTION_LISTS];
	/* available (non-empty) eviction list bitmap rotated so that current
	   @evp is on the most significant bit */
	unsigned long long next_avail_evp;
	/* number of available eviction lists */
	uint32_t num_avail_evps;
	/* current eviction list index */
	uint32_t evp;
	/* callback to determine whether given hash bucket is already
	 * locked by the caller */
	_lru_hash_locked_pfn hash_locked;
	/* optional caller request */
	struct ocf_request *req;
	/* 1 if iterating over clean lists, 0 if over dirty */
	bool clean : 1;
	/* 1 if cacheline is to be locked for write, 0 if for read*/
	bool cl_lock_write : 1;
};

#define OCF_EVICTION_CLEAN_SIZE 32U

struct ocf_part_cleaning_ctx {
	ocf_cache_t cache;
	struct ocf_refcnt counter;
	ocf_cache_line_t cline[OCF_EVICTION_CLEAN_SIZE];
};

struct ocf_user_part {
	struct ocf_user_part_config *config;
	struct ocf_user_part_runtime *runtime;
	ocf_part_id_t id;
	struct ocf_part_cleaning_ctx cleaning;
	struct ocf_lst_entry lst_valid;
};


#endif /* __METADATA_PARTITION_STRUCTS_H__ */
