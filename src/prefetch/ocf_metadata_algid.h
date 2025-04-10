/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_METADATA_ALGID_H__
#define __OCF_METADATA_ALGID_H__

pf_algo_id_t ocf_metadata_get_algorithm_id(struct ocf_cache *cache,
		ocf_cache_line_t line);

void ocf_metadata_set_algorithm_id(
		struct ocf_cache *cache, ocf_cache_line_t line,
		pf_algo_id_t pf_alg_id);

#endif /* __OCF_METADATA_ALGID_H__ */
