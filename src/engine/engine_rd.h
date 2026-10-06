/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __ENGINE_RD_H__
#define __ENGINE_RD_H__

int ocf_read_generic(struct ocf_request *req);

void ocf_read_generic_submit_hit(struct ocf_request *req);

#endif /* __ENGINE_RD_H__ */
