/*
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf_helpers.h"
#include "ocf/ocf.h"
#include "../src/ocf/ocf_def_priv.h"

bool ocf_is_block_size_4k(void)
{
#ifdef OCF_BLOCK_SIZE_4K
	return true;
#else
	return false;
#endif
}
