/*
 * Copyright(c) 2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
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

typedef enum {
	ocf_composite_member_state_attached = 1,
	/* If subvolume is opened it must be attached as well */
	ocf_composite_member_state_opened = 3,
	ocf_composite_member_state_detached = 4,
	ocf_composite_member_state_any = 7,
} ocf_composite_member_state_t;

/**
 * @param[in] subvolume Pointer to a subvolume
 * @param[in] priv Priv
 * @param[in] subvol_status flag with the info if current subvolume is opened,
 *		attached or detached
 */
typedef int (*ocf_composite_volume_member_visitor_t)(ocf_volume_t subvolume,
		void *priv, ocf_composite_member_state_t subvol_status);

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
		ocf_composite_member_state_t subvolume_status);

/**
 * @brief Get subvolume by index in composite volume
 *
 * @param[in] cvolume composite volume handle
 * @param[in] index subvolume index
 *
 * @return subvolume in composite volume
 */
ocf_volume_t ocf_composite_volume_get_subvolume_by_index(
		ocf_composite_volume_t cvolume, int index);

/**
 * @brief Set composite volume UUID
 *
 * @param[in] cvolume Volume
 * @param[in] uuid UUID
 *
 * @return 0 in case of success, error code otherwise
 */
int ocf_composite_volume_set_uuid(ocf_composite_volume_t cvolume,
		struct ocf_volume_uuid *uuid);

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

#endif /* __OCF_COMPOSITE_VOLUME_H__ */
