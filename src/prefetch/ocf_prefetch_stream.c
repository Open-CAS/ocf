/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Sequential length aware prefetch algorithm
 */
#include "ocf_prefetch_stream.h"

#include "ocf_env.h"
#include "ocf_env.h"
#include "ocf_prefetch_priv.h"
#include "ocf/ocf_prefetch_common.h"
#include "../ocf_core_priv.h"
#include "../utils/utils_ohash.h"

#define	MIN_REQ_PER_CELL	16
#define MAX_TOTAL_REQ		(MIN_REQ_PER_CELL << 19)
#define DEFAULT_SECTOR_SIZE     (1 << ENV_SECTOR_SHIFT)
#define	MAX_COUNT		255				/* Max number of sequential requests */
#define	MIN_PF_SECTORS		BYTES_TO_SECTORS(1 * MiB)
#define	MAX_PF_SECTORS		BYTES_TO_SECTORS(MAX_TOTAL_PF)	/* affects MAX_DB_SECTORS */
#define	MAX_DB_SECTORS		15				/* for MAX_DB_SECTORS=8MiB, sector_idx will be 14 */
#if (MAX_TOTAL_PF != (8 * MiB))
#error "MAX_DB_SECTORS must be updated"
#endif
#define	OHASH_SIZE		802816
#define NO_DATA_SECTORS(cnt)	OCF_MAX((2 * MiB) >> ENV_SECTOR_SHIFT, MAX_COUNT * (cnt))
#define OHASH_SECTOR_BITS	(CORE_LINE_BITS + PAGE_SHIFT - ENV_SECTOR_SHIFT) /* 64TB in sectors */

typedef struct ocf_prefetch_stream {
	env_atomic stream_len_db[MAX_COUNT][MAX_DB_SECTORS];
	ohash64_handle_t ohash64_handle;
	uint32_t req_cnt;
} *ocf_prefetch_stream_t ;

typedef union {
	struct {
		uint64_t pfcnt:16;
		uint64_t count:8;
		uint64_t sector:OHASH_SECTOR_BITS;
		uint64_t unused;
	};
	uint64_t raw;
} ohash_t;

static const ohash_t c_mask = {
	.pfcnt = 0,
	.count = 0,
	.sector = ~0,	/* mask includes all sector bits */
	.unused = 0
};
/* ===========================================================================*/
static inline void clear_stat_on_need(ocf_prefetch_stream_t pf)
{
	if (++pf->req_cnt > MAX_TOTAL_REQ) {
		env_memset(pf->stream_len_db, sizeof(pf->stream_len_db), 0);
		pf->req_cnt = 0;
	}
}

/* ===========================================================================*/
/* Get the relevant ohash item with the new count */
static uint64_t get_ohash_item(ohash64_handle_t *hash,
			       uint64_t sector, uint32_t cnt)
{
	ohash_t item = { .sector = sector };

	item.raw = ocf_ohash_get(hash, item.raw, c_mask.raw);

	/* existing streams reaching to max length are truncated and handled
	 * as new streams */
	if (unlikely(item.count == MAX_COUNT))
		item.count = 0;

	/* new entry will have all values zeroed, outside sector - which is
	 * overridden below */
	item.count++;

	/* The next expected READ */
	item.sector = sector + cnt;

	return item.raw;
}

/* ===========================================================================*/
/* Set the prefetch threshold = 80% */
#define	PCT_80(_n)	(((uint64_t)(_n) << 2) / 5)

static inline uint32_t calc_threshold(uint32_t threshold)
{
	return (uint32_t)PCT_80(threshold);
}

/* ===========================================================================*/
/* Sequence Length Aware Prefetch algorithm */
void ocf_pf_stream_get_info(ocf_prefetch_t _pf, ocf_pf_req_info_t *req_info)
{
	ocf_prefetch_stream_t pf = (ocf_prefetch_stream_t)_pf;
	uint i;
	ohash_t item;
	ohash64_handle_t *hash = NULL;
	uint64_t sector;
	uint32_t sector_cnt, sector_idx, sec_to_pf, cur_cnt, pf_threshold;

	if (unlikely(pf == NULL)) {
		ENV_WARN(true, "pf is NULL\n");
		return;
	}

	sector = BYTES_TO_SECTORS(req_info->addr);
	sector_cnt = BYTES_TO_SECTORS(req_info->len + DEFAULT_SECTOR_SIZE - 1);
	// sector_idx is in range 0..32
	sector_idx = (sector_cnt <= 1) ? 0 : (32-__builtin_clz(sector_cnt - 1));

	/* Check if need to clear statistics */
	clear_stat_on_need(pf);

	/* Get info from hash table */
	hash = &pf->ohash64_handle;
	item.raw = get_ohash_item(hash, sector, sector_cnt);

	/* Max prefetch is 8MB, skip requests that are larger than that */
	if (sector_cnt > MAX_PF_SECTORS)
		goto done;

	cur_cnt = env_atomic_inc_return(&pf->stream_len_db[item.count - 1][sector_idx]);

	/* Prefetched stream is longer then this request:
	 * 1. reduce this request.
	 * 2. if leftover is <= 1MiB, continue to prefetch
	 */
	if (item.pfcnt >= sector_cnt) {
		item.pfcnt -= sector_cnt;
		if ((item.pfcnt > sector_cnt) &&
		   ((item.pfcnt - sector_cnt) > OCF_MAX(MIN_PF_SECTORS, sector_cnt)))
			goto done;
	} else {
		item.pfcnt = 0;
	}

	/* Do not predict not enough info in stream_len_db */
	if (cur_cnt < MIN_REQ_PER_CELL)
		goto done;

	pf_threshold = calc_threshold(cur_cnt);
	for (i = item.count; i < MAX_COUNT; i++) {
		uint32_t cnt = env_atomic_read(&pf->stream_len_db[i][sector_idx]);
		if (cnt < pf_threshold || cnt > cur_cnt)
			break;

		cur_cnt = cnt;
	}

	sec_to_pf = (i - item.count) * sector_cnt;

	/* Reached end of stream_len_db info, prefetch atleast NO_DATA_SECTORS... */
	if (i == MAX_COUNT)
		sec_to_pf = NO_DATA_SECTORS(sector_cnt);

	/* Do not overflow ohash_t.pfcnt */
	sec_to_pf = OCF_MIN(sec_to_pf, MAX_PF_SECTORS);

	/* Do not prefetch partial requests */
	if (sec_to_pf < sector_cnt)
		goto done;

	if (sec_to_pf > item.pfcnt) {
		req_info->len = SECTORS_TO_BYTES(sec_to_pf) - SECTORS_TO_BYTES((u64)item.pfcnt);
		req_info->addr = SECTORS_TO_BYTES((u64)item.sector) + SECTORS_TO_BYTES((u64)item.pfcnt);

		req_info->pa_id = pa_id_stream;
		item.pfcnt = sec_to_pf;
	}

done:
	ocf_ohash_set(hash, item.raw, c_mask.raw);
}

/* ===========================================================================*/
/* Create the prefetch database per core */
void ocf_pf_stream_create(ocf_core_t core)
{
	const pf_algo_id_t pa_id = pa_id_stream;
	ocf_prefetch_stream_t pf = NULL;

	if (unlikely(core == NULL)) {
		ENV_WARN(true, "Core Handle is NULL\n");
		return;
	}
	core->ocf_prefetch_handles[pa_id] =
		env_aligned_zalloc(ENV_PROCESSOR_CACHE_LINE_SIZE,
				       sizeof(struct ocf_prefetch_stream));
	pf = (ocf_prefetch_stream_t)core->ocf_prefetch_handles[pa_id];
	if (unlikely(pf == NULL)) {
		ENV_WARN(true, "env_aligned_zalloc(%lu) failed\n",
				sizeof(struct ocf_prefetch_stream));
	} else {
		ocf_ohash_create(core, &pf->ohash64_handle, OHASH_SIZE, "prefetch");
	}
}

/* ===========================================================================*/
/* Destroy the prefetch database per core */
void ocf_pf_stream_destroy(ocf_core_t core)
{
	const pf_algo_id_t pa_id = pa_id_stream;
	ocf_prefetch_stream_t pf = NULL;
	if (unlikely(core == NULL)) {
		ENV_WARN(true, "NULL Core Handle\n");
		return;
	}
	if (unlikely((pf = core->ocf_prefetch_handles[pa_id]) == NULL)) {
		ENV_WARN(true, "NULL Prefetch Handle\n");
		return;
	}

	core->ocf_prefetch_handles[pa_id] = NULL;
	ocf_ohash_destroy(&pf->ohash64_handle);
	env_aligned_free(pf);
}
