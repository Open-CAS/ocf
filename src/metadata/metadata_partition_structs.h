/*
 * Copyright(c) 2012-2020 Intel Corporation
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

/* Iterator state, visiting all eviction lists within a partition
   in round robin order */
struct ocf_lru_iter {
	/* cache object */
	ocf_cache_t cache;
	/* target partition id */
	ocf_part_id_t part_id;
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
};

struct ocf_user_part {
	struct ocf_user_part_config *config;
	struct ocf_user_part_runtime *runtime;

	struct ocf_lru_iter eviction_clean_iter;
	uint32_t next_eviction_list;
	struct ocf_lst_entry lst_valid;
};


#endif /* __METADATA_PARTITION_STRUCTS_H__ */
