/*
 * Copyright(c) 2012-2018 Intel Corporation
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
        struct eviction_policy eviction;
        struct cleaning_policy cleaning;
};

struct ocf_user_part {
        struct ocf_user_part_config *config;
        struct ocf_user_part_runtime *runtime;

        struct ocf_lst_entry lst_valid;
};


#endif /* __METADATA_PARTITION_STRUCTS_H__ */
