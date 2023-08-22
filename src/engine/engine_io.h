/*
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ENGINE_IO_H_
#define ENGINE_IO_H_

#include "../ocf_request.h"

void ocf_engine_forward_cache_io(struct ocf_request *req, int dir,
		uint64_t offset, uint64_t size, ocf_req_end_t callback);

void ocf_engine_forward_cache_io_req(struct ocf_request *req, int dir,
		ocf_req_end_t callback);

void ocf_engine_forward_cache_flush_req(struct ocf_request *req,
		ocf_req_end_t callback);

void ocf_engine_forward_cache_discard_req(struct ocf_request *req,
		ocf_req_end_t callback);

void ocf_engine_forward_core_io_req(struct ocf_request *req,
		ocf_req_end_t callback);

void ocf_engine_forward_core_flush_req(struct ocf_request *req,
		ocf_req_end_t callback);

void ocf_engine_forward_core_discard_req(struct ocf_request *req,
		ocf_req_end_t callback);

#endif /* ENGINE_IO_H_ */
