/*
 * Copyright(c) 2023 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_MNGT_FLUSH_PRIV_H__
#define __OCF_MNGT_FLUSH_PRIV_H__

#include <ocf/ocf_types.h>

/**
 * @brief Detach range of clines from a given cache
 *
 * @param[in] cache Cache handle
 * @param[in] begin begin of the cache line range
 * @param[in] end end of the cache line range
 * @param[in] cmpl Completion callback
 * @param[in] priv Completion callback context
 */
void ocf_mngt_cache_detach_cline_range(ocf_cache_t cache,
		ocf_cache_line_t begin, ocf_cache_line_t end,
		ocf_mngt_cache_purge_end_t cmpl, void *priv);

/**
 * @brief Move range of cache lines to free_detached and mark as unavailable
 *
 * @param[in] cache Cache handle
 * @param[in] begin Begin of the range
 * @param[in] end End of the range
 */
int ocf_mngt_cache_attach_cline_range(ocf_cache_t cache,
		ocf_cache_line_t first_cline, ocf_cache_line_t last_cline);

#endif /* __OCF_MNGT_FLUSH_PRIV_H__ */
