/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */


#ifndef __OCF_CFG_H__
#define __OCF_CFG_H__

/**
 * @file
 * @brief OCF configuration file
 */

/**
 * Configure maximum numbers of cores in cache instance
 */
#ifndef OCF_CONFIG_MAX_CORES
#define OCF_CONFIG_MAX_CORES 4095
#endif

/** Maximum number of IO classes that can be configured */
#define OCF_IO_CLASSES_BITS 3
#ifndef OCF_CONFIG_MAX_IO_CLASSES
/**
 * Maximum number of IO classes must leave another value for free list.
 * see PARTITION_FREELIST definition
 */
#define OCF_CONFIG_MAX_IO_CLASSES ((1 << OCF_IO_CLASSES_BITS) - 2)
#endif

#if OCF_CONFIG_MAX_IO_CLASSES > ((1 << OCF_IO_CLASSES_BITS) - 2)
#error "Limit of maximum number of IO classes exceeded"
#endif

/** Enabling debug statistics */
#ifndef OCF_CONFIG_DEBUG_STATS
#define OCF_CONFIG_DEBUG_STATS 0
#endif

#endif /* __OCF_CFG_H__ */
