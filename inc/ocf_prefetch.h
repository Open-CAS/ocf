/*
 * Copyright(c) 2021-2024 Huawei Technologies Co., Ltd.
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_PREFETCH_H__
#define __OCF_PREFETCH_H__

#include "ocf_def.h"

/*
 * Prefetch policy id
 */
typedef enum {
	ocf_pf_none = -1,
	ocf_pf_readahead = 0,
	ocf_pf_num,
} ocf_pf_id_t;

typedef uint8_t ocf_pf_mask_t;

/* The bitmask must fit all the values of ocf_pf_id_t */
_Static_assert(OCF_BITWIDTH(ocf_pf_mask_t) >= ocf_pf_num);

#define OCF_PF_MASK_DEFAULT 0

#endif /* __OCF_PREFETCH_H__ */
