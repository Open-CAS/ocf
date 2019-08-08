/*
 * Copyright(c) 2019-2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_FREELIST_H__
#define __OCF_FREELIST_H__

#include "ocf_cache_priv.h"

struct ocf_freelist;

typedef struct ocf_freelist *ocf_freelist_t;

/* Init / deinit freelist runtime structures */
ocf_freelist_t ocf_freelist_init(struct ocf_cache *cache);
void ocf_freelist_deinit(ocf_freelist_t freelist);

/* Assign unused cachelines to freelist */
void ocf_freelist_populate(ocf_freelist_t freelist,
		ocf_cache_line_t num_free_clines);

/* Get cacheline from freelist */
bool ocf_freelist_get_cache_line(ocf_freelist_t freelist,
		ocf_cache_line_t *cline);

/* Put cacheline back to freelist */
void ocf_freelist_put_cache_line(ocf_freelist_t freelist,
		ocf_cache_line_t cline);

/* Return total number of free cachelines */
ocf_cache_line_t ocf_freelist_num_free(ocf_freelist_t freelist);

#endif /* __OCF_FREELIST_H__ */
