/*
 * Copyright(c) 2012-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __ENGINE_WT_H__
#define __ENGINE_WT_H__

int ocf_write_wt(struct ocf_request *req);

bool ocf_write_wt_fast(struct ocf_request *req);

#endif /* __ENGINE_WT_H__ */
