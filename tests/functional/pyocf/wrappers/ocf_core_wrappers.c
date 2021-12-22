/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf_io.h"
#include "ocf/ocf_core.h"

const struct ocf_volume_uuid *ocf_core_get_uuid_wrapper(ocf_core_t core)
{
	return ocf_core_get_uuid(core);
}


