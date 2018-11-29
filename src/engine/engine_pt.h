/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef ENGINE_OFF_H_
#define ENGINE_OFF_H_

int ocf_read_pt(struct ocf_request *rq);

int ocf_read_pt_do(struct ocf_request *rq);

void ocf_engine_push_rq_front_pt(struct ocf_request *rq);

#endif /* ENGINE_OFF_H_ */
