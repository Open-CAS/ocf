/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */


#ifndef __OCF_MNGT_COMMON_H__
#define __OCF_MNGT_COMMON_H__

int cache_mng_core_close(ocf_cache_t cache, ocf_core_id_t core_id);

void cache_mng_core_remove_from_meta(struct ocf_cache *cache, int core_id);

void cache_mng_core_remove_from_cache(struct ocf_cache *cache, int core_id);

void cache_mng_core_deinit_attached_meta(struct ocf_cache *cache, int core_id);

void cache_mng_core_remove_from_cleaning_pol(struct ocf_cache *cache,
		int core_id);

int _ocf_cleaning_thread(void *priv);

int cache_mng_thread_io_requests(void *data);

bool ocf_mngt_cache_is_dirty(ocf_cache_t cache);

int ocf_mngt_add_partition_to_cache(struct ocf_cache *cache,
		ocf_part_id_t part_id, const char *name, uint32_t min_size,
		uint32_t max_size, uint8_t priority, bool valid);

bool ocf_mngt_is_cache_locked(ocf_cache_t cache);

typedef struct ocf_mngt_pipeline *ocf_mngt_pipeline_t;

typedef void (*ocf_mngt_pipeline_step_t)(ocf_mngt_pipeline_t pipeline,
		void *priv);

typedef void (*ocf_mngt_pipeline_end_t)(ocf_mngt_pipeline_t pipeline,
		void *priv, int error);

int ocf_mngt_pipeline_create(ocf_mngt_pipeline_t *pipeline, ocf_cache_t cache,
		ocf_mngt_pipeline_step_t *steps, ocf_mngt_pipeline_end_t cmpl,
		void *priv);

void ocf_mngt_pipeline_destroy(ocf_mngt_pipeline_t pipeline);

void ocf_mngt_pipeline_next(ocf_mngt_pipeline_t pipeline);

void ocf_mngt_pipeline_finish(ocf_mngt_pipeline_t pipeline, int error);

#endif /* __OCF_MNGT_COMMON_H__ */
