/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __UTILS_CORE_H__
#define __UTILS_CORE_H__

#define for_each_core(cache, iter) \
	for (iter = 0; iter < OCF_CORE_MAX; iter++) \
		if (cache->core_conf_meta[iter].added)

#endif /* __UTILS_CORE_H__ */
