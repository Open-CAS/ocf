/*
 * Copyright(c) 2022 Intel Corporation
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_COMPOSITE_VOLUME_H__
#define __OCF_COMPOSITE_VOLUME_H__

/**
 * @file
 * @brief OCF composite volume API
 */

#include "ocf_types.h"
#include "ocf_env_headers.h"
#include "ocf_err.h"
#include "ocf_volume.h"

#define OCF_VOLUME_TYPE_COMPOSITE 10

#ifdef OCF_DEBUG_STATS
#include "ocf_stats.h"
#define OCF_COMPOSITE_VOLUME_MEMBER_STATS_GET_INDEX(core_id, part_id) \
	(core_id * OCF_USER_IO_CLASS_MAX + part_id)

typedef struct ocf_composite_volume_counters_block *ocf_composite_volume_counters_block_t;

typedef struct ocf_composite_volume_stats_block *ocf_composite_volume_stats_block_t;

struct stats_ctx {
	uint16_t core_id;

	uint16_t part_id;

	uint16_t composite_volume_member_id;
};
#endif

/**
 * @brief handle to object designating composite volume
 */
typedef ocf_volume_t ocf_composite_volume_t;

/**
 * @brief Allocate and initialize composite volume
 *
 * @param[out] cvolume pointer to volume handle
 * @param[in] ctx OCF context
 *
 * @return Zero when success, othewise an error
 */
int ocf_composite_volume_create(ocf_composite_volume_t *cvolume, ocf_ctx_t ctx);

/**
 * @brief Deinitialize and free composite volume
 *
 * @param[in] volume volume handle
 */
void ocf_composite_volume_destroy(ocf_composite_volume_t cvolume);

typedef enum  {
	ocf_composite_visitor_member_state_attached = 1,
	/* If subvolume is opened it must be attached as well */
	ocf_composite_visitor_member_state_opened = 3,
	ocf_composite_visitor_member_state_detached = 4,
	ocf_composite_visitor_member_state_any = 7,
} ocf_composite_visitor_member_state_t;

/**
 * @param[in] subvolume Pointer to a subvolume
 * @param[in] priv Priv
 * @param[in] subvol_status flag with the info if current subvolume is opened,
 *		attached or detached
 */
typedef int (*ocf_composite_volume_member_visitor_t)(ocf_volume_t subvolume,
		void *priv, ocf_composite_visitor_member_state_t subvol_status);

/**
 * @brief Call @visitor on every valid member of composite volume
 *
 * @param[in] cvolume composite volume handle
 * @param[in] visitor function callback
 * @param[in] priv pointer to be passed to the callback
 * @param[in] subvol_status info whether iterate over
 *		opened/attached/detached/all volumes
 *
 * @return 0 if the visitor function was called for all subvolumes, error code
 *		otherwise
 */
int ocf_composite_volume_member_visit(ocf_composite_volume_t cvolume,
		ocf_composite_volume_member_visitor_t visitor, void *priv,
		ocf_composite_visitor_member_state_t subvolume_status);

/**
 * @brief Get subvolume by index in composite volume
 *
 * @param[in] cvolume composite volume handle
 * @param[in] index subvolume index
 *
 * @return subvolume in composite volume
 */
ocf_volume_t ocf_composite_volume_get_subvolume_by_index(ocf_composite_volume_t cvolume, int index);

/**
 * @brief Get range of addresses from a subvolume
 *
 * @param[in] cvolume composite volume handle
 * @param[in] subvolume_id subvolume index
 * @param[out] begin_addr begining of the address range
 * @param[out] end_addr end of the address range
 *
 * @return 0 in case of success, error code otherwise
 */
int ocf_composite_volume_get_subvolume_addr_range(
		ocf_composite_volume_t cvolume, uint8_t subvolume_id,
		uint64_t *begin_addr, uint64_t *end_addr);

/**
 * @brief Set volume UUID
 *
 * @param[in] volume Volume
 * @param[in] uuid UUID
 *
 * @return None
 */
void ocf_composite_volume_set_uuid(ocf_composite_volume_t cvolume, struct ocf_volume_uuid* uuid,
	bool uuid_copy);


/**
 * @brief Get volume's id by UUID
 *
 * @param[in] volume Volume
 * @param[in] uuid UUID
 *
 * @return id of the matching subvolume or error if the volume wasn't found
 */
int ocf_composite_volume_get_id_from_uuid(ocf_composite_volume_t cvolume,
		ocf_uuid_t target_uuid);

#ifdef OCF_DEBUG_STATS
/**
 * @brief Update stats to composite volume
 *
 * @param[in] core core volume
 * @param[in] master_io io to composite_volume
 * @param[in] par_id part_id
 * @param[in] dir io direction
 * @param[in] pa_id prefetch type
 *
 * @return None
 */
void ocf_composite_volume_update_stats(ocf_core_t core, ocf_io_t master_io,
		ocf_part_id_t part_id, int dir, pf_algo_id_t pa_id);

int ocf_composite_volume_stats_initialize(ocf_cache_t cache, ocf_core_t core,
	int composite_volume_member_id);

int ocf_composite_volume_stats_initialize_all_cores(ocf_cache_t cache,
	int composite_volume_member_id);

typedef int (*ocf_composite_volume_get_stats_t)(struct stats_ctx stats,
	ocf_composite_volume_stats_block_t total, ocf_cache_t cache);

int _composite_volume_member_stats_cache(struct stats_ctx stats,
	ocf_composite_volume_stats_block_t total, ocf_cache_t cache);

int _composite_volume_member_stats_core(struct stats_ctx stats,
	ocf_composite_volume_stats_block_t total, ocf_cache_t cache);

int _composite_volume_member_stats_part_cache(struct stats_ctx stats,
	ocf_composite_volume_stats_block_t total, ocf_cache_t cache);

int _composite_volume_member_stats_part_core(struct stats_ctx stats,
	ocf_composite_volume_stats_block_t total, ocf_cache_t cache);

int ocf_composite_volume_get_member_stats(ocf_cache_t cache, struct stats_ctx stats,
	struct ocf_stats_blocks *blocks, ocf_composite_volume_get_stats_t collect_stats);
#endif

#endif /* __OCF_COMPOSITE_VOLUME_H__ */
