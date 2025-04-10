/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_CORE_PRIV_H__
#define __OCF_CORE_PRIV_H__

#include "ocf/ocf.h"
#include "ocf_env.h"
#include "ocf_ctx_priv.h"
#include "ocf_volume_priv.h"
#include "ocf_seq_cutoff.h"
#include "classifier/ocf_classifier.h"
#include "utils/utils_pipeline.h"

typedef enum {
	mode_disabled,
	mode_enabled,
	mode_none,
	mode_max
} ocf_enable_disable_param_mode_t;

#define ocf_core_log_prefix(core, lvl, prefix, fmt, ...) \
	ocf_cache_log_prefix(ocf_core_get_cache(core), lvl, ".%s" prefix, \
			fmt, ocf_core_get_name(core), ##__VA_ARGS__)

#define ocf_core_log(core, lvl, fmt, ...) \
	ocf_core_log_prefix(core, lvl, ": ", fmt, ##__VA_ARGS__)

struct ocf_metadata_uuid {
	uint32_t size;
	uint8_t data[OCF_VOLUME_UUID_MAX_SIZE];
} __packed;

#define OCF_CORE_USER_DATA_SIZE 64

struct ocf_core_meta_config {
	char name[OCF_CORE_NAME_SIZE];

	uint8_t type;

	/* This bit means that object was saved in cache metadata */
	uint32_t valid : 1;

	/* Core sequence number used to correlate cache lines with cores
	 * when recovering from atomic device */
	ocf_seq_no_t seq_no;

	/* Sequential cutoff threshold (in bytes) */
	env_atomic seq_cutoff_threshold;

	/* Sequential cutoff policy */
	env_atomic seq_cutoff_policy;

	/* Sequential cutoff stream promotion request count */
	env_atomic seq_cutoff_promo_count;

	/* Sequential cutoff stream promote on threshold */
	env_atomic seq_cutoff_promote_on_threshold;

	/* core object size in bytes */
	uint64_t length;

	uint8_t user_data[OCF_CORE_USER_DATA_SIZE];
};

struct ocf_core_meta_runtime {
	/* Number of blocks from that objects that currently are cached
	 * on the caching device.
	 */
	env_atomic cached_clines;
	env_atomic dirty_clines;
	env_atomic initial_dirty_clines;

	env_atomic64 dirty_since;

	struct {
		/* clines within lru list (?) */
		env_atomic cached_clines;
		/* dirty clines assigned to this specific partition within
		 * cache device
		 */
		env_atomic dirty_clines;
	} part_counters[OCF_USER_IO_CLASS_MAX];
};

struct ocf_core_volume_uuid {
	char cache_name[OCF_CACHE_NAME_SIZE];
	char core_name[OCF_CORE_NAME_SIZE];
};

struct ocf_core {
	ocf_cache_t cache;
	struct ocf_volume front_volume;
	struct ocf_volume *volume;

	struct ocf_core *lower_core;
	struct ocf_core *upper_core;

	struct ocf_core_meta_config *conf_meta;
	struct ocf_core_meta_runtime *runtime_meta;

	struct ocf_seq_cutoff *seq_cutoff;

	env_atomic flushed;

	uint32_t minimal_io_size;

	/* This bit means that core volume is initialized */
	uint32_t has_volume : 1;
	/* This bit means that core volume is open */
	uint32_t opened : 1;
	/* This bit means that core is added into cache */
	uint32_t added : 1;

	struct ocf_counters_core *counters;
	/* Per core classifier, default value taken frm cache */
	uint8_t ocf_classifier;
	/* Per core prefetcher, default value taken frm cache */
	uint8_t ocf_prefetcher;

	void *ocf_prefetch_handles[pa_id_num];	/* OCF: Prefetch Handles */

	/* OCF: Classifier Handlers */
	#define X(classifier)	void *classifier_handler_##classifier;
	OCF_CLASSIFIER_HANDLERS_X
	#undef X

	void *priv;
};

bool ocf_core_is_valid(ocf_cache_t cache, ocf_core_id_t id);

ocf_core_id_t ocf_core_get_id(ocf_core_t core);

int ocf_core_volume_type_init(ocf_ctx_t ctx);

int ocf_core_get_front_uuid(ocf_core_t core,
		struct ocf_core_volume_uuid *core_uuid);

struct ocf_request *ocf_io_to_req(ocf_io_t io);

#endif /* __OCF_CORE_PRIV_H__ */
