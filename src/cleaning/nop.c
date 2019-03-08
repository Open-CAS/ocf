/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "nop.h"
#include "../ocf_cache_priv.h"

void cleaning_nop_perform_cleaning(ocf_cache_t cache, ocf_cleaner_end_t cmpl)
{
	uint32_t interval = SLEEP_TIME_MS;
	cmpl(&cache->cleaner, interval);
}
