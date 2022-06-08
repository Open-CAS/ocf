/*
 * Copyright(c) 2022 Intel Corporation
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

/**
 * @brief Add subvolume to composite volume
 *
 * @param[in] cvolume composite volume handle
 * @param[in] type type of added subvolume
 * @param[in] uuid UUID of added subvolume
 * @param[in] volume_params params to be passed to subvolume open
 *
 * @return Zero when success, othewise an error
 */
int ocf_composite_volume_add(ocf_composite_volume_t cvolume,
		ocf_volume_type_t type, struct ocf_volume_uuid *uuid,
		void *volume_params);

#endif /* __OCF_COMPOSITE_VOLUME_H__ */
