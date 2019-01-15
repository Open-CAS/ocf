/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __DOBJ_H__
#define __DOBJ_H__

#include <ocf/ocf.h>
#include "ocf_env.h"
#include "ctx.h"
#include "data.h"

struct dobj_io {
	struct dobj_data *data;
	uint32_t offset;
};

struct dobj {
	uint8_t *mem;
	const char *name;
};

int dobj_init(ocf_ctx_t ocf_ctx);
void dobj_cleanup(ocf_ctx_t ocf_ctx);

#endif
