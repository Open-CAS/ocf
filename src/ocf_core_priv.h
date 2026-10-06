/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_CORE_PRIV_H__
#define __OCF_CORE_PRIV_H__

#include "ocf/ocf.h"
#include "ocf_env.h"
#include "ocf_ctx_priv.h"
#include "ocf_volume_priv.h"
#include "ocf_seq_detect.h"
#include "ocf/ocf_prefetch.h"
#include "metadata/metadata_core.h"

#define ocf_core_log_prefix(core, lvl, prefix, fmt, ...) \
	ocf_cache_log_prefix(ocf_core_get_cache(core), lvl, ".%s" prefix, \
			fmt, ocf_core_get_name(core), ##__VA_ARGS__)

#define ocf_core_log(core, lvl, fmt, ...) \
	ocf_core_log_prefix(core, lvl, ": ", fmt, ##__VA_ARGS__)

struct ocf_core_volume_uuid {
	char cache_name[OCF_CACHE_NAME_SIZE];
	char core_name[OCF_CORE_NAME_SIZE];
};

struct ocf_core {
	struct ocf_volume front_volume;
	struct ocf_volume volume;

	struct ocf_core_meta_config *conf_meta;
	struct ocf_core_meta_runtime *runtime_meta;

	struct ocf_seq_detect *seq_detect;

	void *pf_priv[ocf_pf_num];
	bool seq_cutoff_active;

	env_atomic flushed;

	/* This bit means that core volume is initialized */
	uint32_t has_volume : 1;
	/* This bit means that core volume is open */
	uint32_t opened : 1;
	/* This bit means that core is added into cache */
	uint32_t added : 1;

	struct ocf_counters_core *counters;

	void *priv;
};

bool ocf_core_is_valid(ocf_cache_t cache, ocf_core_id_t id);

ocf_core_id_t ocf_core_get_id(ocf_core_t core);

int ocf_core_volume_type_init(ocf_ctx_t ctx);

struct ocf_request *ocf_io_to_req(ocf_io_t io);

#endif /* __OCF_CORE_PRIV_H__ */
