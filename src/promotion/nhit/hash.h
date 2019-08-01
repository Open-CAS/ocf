/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef NHIT_HASH_H_
#define NHIT_HASH_H_

#include "ocf/ocf.h"

typedef struct nhit_hash *nhit_hash_t;

ocf_error_t hash_init(uint64_t hash_size, nhit_hash_t *ctx);

void hash_deinit(nhit_hash_t ctx);

void hash_insert(nhit_hash_t ctx, ocf_core_id_t core_id, uint64_t core_lba);

bool hash_query(nhit_hash_t ctx, ocf_core_id_t core_id, uint64_t core_lba,
		int32_t *counter);

void hash_set_occurences(nhit_hash_t ctx, ocf_core_id_t core_id,
		uint64_t core_lba, int32_t occurences);

#endif /* NHIT_HASH_H_ */
