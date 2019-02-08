/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_VOLUME_PRIV_H__
#define __OCF_VOLUME_PRIV_H__

#include "ocf_env.h"
#include "ocf_io_priv.h"

struct ocf_volume_type {
	const struct ocf_volume_properties *properties;
	env_allocator *allocator;
};

struct ocf_volume {
	ocf_volume_type_t type;
	struct ocf_volume_uuid uuid;
	bool opened;
	bool uuid_copy;
	void *priv;
	ocf_cache_t cache;
	struct list_head core_pool_item;
	struct {
		unsigned discard_zeroes:1;
			/* true if reading discarded pages returns 0 */
	} features;
};

int ocf_volume_type_init(struct ocf_volume_type **type,
		const struct ocf_volume_properties *properties);

void ocf_volume_type_deinit(struct ocf_volume_type *type);

void ocf_volume_move(ocf_volume_t volume, ocf_volume_t from);

void ocf_volume_set_uuid(ocf_volume_t volume,
		const struct ocf_volume_uuid *uuid);

static inline void ocf_volume_submit_metadata(struct ocf_io *io)
{
	ENV_BUG_ON(!io->volume->type->properties->ops.submit_metadata);

	io->volume->type->properties->ops.submit_metadata(io);
}

static inline void ocf_volume_submit_write_zeroes(struct ocf_io *io)
{
	ENV_BUG_ON(!io->volume->type->properties->ops.submit_write_zeroes);

	io->volume->type->properties->ops.submit_write_zeroes(io);
}

#endif  /*__OCF_VOLUME_PRIV_H__ */
