/*
 * Copyright(c) 2023 Huawei Technologies Co., Ltd.
 * Copyright(c) 2026 Unvertical
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

#endif /* __OCF_MNGT_FLUSH_PRIV_H__ */
