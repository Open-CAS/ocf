/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Admission algorithm based on chunks write hotness.
 */

#include "../ocf_core_priv.h"
#include "ocf_classifier.h"
#include "../utils/utils_ohash.h"

#define CHUNK_BITS	22
#define CHUNK_SIZE	(1LL << CHUNK_BITS)
#define CHUNK_WFCT	100
#define OHASH_SIZE	802816

typedef union {
	struct {
		uint32_t chunk;
		int32_t bytes;
	};
	uint64_t raw;
} ohash_t;

OCF_CLASSIFIER(write_chunks, ohash64_handle_t, 1)
{
	static const ohash_t c_mask = { .chunk = ~0, .bytes = 0 };
	uint64_t addr = req->addr;
	uint64_t len = req->bytes;
	uint64_t chunks = ((addr + len) >> CHUNK_BITS) - (addr >> CHUNK_BITS) + 1;
	uint64_t wbytes = CHUNK_WFCT * chunks * CHUNK_SIZE / 100;
	int32_t bytes = 0;

	ENV_BUILD_BUG_ON(sizeof(c_mask.chunk)*8 < CHUNK_BITS);

	while (len > 0) {
		uint32_t chunk = addr >> CHUNK_BITS;
		uint32_t len_in_chunk = OCF_MIN(len, CHUNK_SIZE - (addr & (CHUNK_SIZE - 1)));
		ohash_t item = { .chunk = chunk };

		item.raw = ocf_ohash_get_locked(get_classifier_handler(req->core), item.raw, c_mask.raw, true);
		if (item.chunk != chunk)
			item.chunk = chunk;

		bytes += item.bytes;
		if (req->rw == OCF_READ)
			item.bytes += len_in_chunk;
		else
			item.bytes -= len_in_chunk;

		// Forget chunk status once in a while
		if (abs(item.bytes) > CHUNK_SIZE*8)
			item.bytes = 0;

		ocf_ohash_set_locked(get_classifier_handler(req->core), item.raw, c_mask.raw, true);

		len -= len_in_chunk;
		addr += len_in_chunk;
	}

	if ((bytes < 0) && (abs(bytes) > wbytes))
		return true;

	return false;
}
