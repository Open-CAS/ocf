/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#pragma once

#define OCF_JOURNAL_DEBUG 1

typedef uint32_t ocf_journal_idx_t;

struct ocf_journal_op {
#if OCF_JOURNAL_DEBUG
	struct ocf_journal *jrnl;
#endif
	ocf_journal_idx_t parent; /* op idx to jump to when finishing this op */
	ocf_journal_idx_t desc_visited; /* op idx to jump to next child */
	ocf_journal_idx_t ring_idx;
	ocf_journal_idx_t ring_capacity;
	struct ocf_jdata data;
	enum ocf_journal_op_id id;
	bool started : 1;
	bool finished : 1;
};

struct ocf_journal_hdr
{
	bool initialized;
	bool full;
	ocf_journal_idx_t capacity;	// excluding header, ops unit
	ocf_journal_idx_t started_idx;	// incremented atomically when starting
					// transaction (with increment = number
					//  of operations in transaction)
	ocf_journal_idx_t finished_idx; // incremented atomically when finishing
					// transaction - all operations in ring
					// buffer belonging to one or more
					// finished transactions should all be
					// marked as finished
	struct ocf_journal_op ring[];
};

struct ocf_journal_ring
{
	struct ocf_journal_hdr *hdr;
	struct ocf_journal_op *buff;
};

struct ocf_journal {
	struct ocf_journal_schema *schema;
	env_mutex mutex;
	struct ocf_journal_ring ring;
	size_t buf_size;
};

ocf_jop_t ocf_journal_get_next(ocf_jop_t op);
ocf_jop_t ocf_journal_op_get_parent(ocf_jop_t op);

typedef void (*ocf_journal_schema_dfs_cb_t)(struct ocf_journal_schema *schema,
		enum ocf_journal_op_id op_id, unsigned cnt, void *ctx);
