/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_UPDATER_PRIV_H__
#define __METADATA_UPDATER_PRIV_H__

#include "../ocf_def_priv.h"
#include "metadata_io.h"

struct ocf_metadata_updater {
	/* Metadata flush synchronizer context */
	struct ocf_metadata_io_syncher {
		struct list_head in_progress_head;
		struct list_head pending_head;
		env_mutex lock;
	} syncher;

	void *priv;
};


void metadata_updater_submit(struct metadata_io_request *m_req);

int ocf_metadata_updater_init(struct ocf_cache *cache);

void ocf_metadata_updater_kick(struct ocf_cache *cache);

void ocf_metadata_updater_stop(struct ocf_cache *cache);

#endif /* __METADATA_UPDATER_PRIV_H__ */
