/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#pragma once

#include "utils_journal_lru_data.h"

struct ocf_jdata_val_update {
	uint32_t old;
	uint32_t new;
};

struct ocf_jdata {
	union {
		struct ocf_jdata_lru_del lru_del;
		struct ocf_jdata_lru_unlink lru_unlink;
		struct ocf_jdata_lru_move lru_move;
		struct ocf_jdata_lru_del_update_pointers del_update_ptrs;
		struct ocf_jdata_lru_del_dec_count del_dec_count;
		struct ocf_jdata_lru_del_dec_hot del_dec_hot;
		struct ocf_jdata_val_update balance_update_ctr;
		struct ocf_jdata_val_update balance_update_last;
		struct ocf_jdata_val_update swap;
		struct ocf_jdata_lru_list lru_list;
		struct ocf_jdata_lru_balance_set_hot balance_set_hot;
		struct ocf_jdata_lru_add_insert insert;
	};
};


struct ocf_journal;
struct ocf_journal_op;

typedef struct ocf_journal *ocf_journal_t;
typedef struct ocf_journal_op *ocf_jop_t;

#define OCF_JOURNAL_OP_INIT_VAL() NULL

enum ocf_journal_op_id {
	ocf_journal_op_id_lru_invalid = 0, //entry being zeroed, ignore
	ocf_journal_op_id_lru_repart,
	ocf_journal_op_id_lru_del,
	ocf_journal_op_id_lru_unlink,
	ocf_journal_op_id_lru_update_ptrs,
	ocf_journal_op_id_lru_dec_count,
	ocf_journal_op_id_lru_clear_elem,
	ocf_journal_op_id_lru_balance,
	ocf_journal_op_id_lru_balance_update_ctr,
	ocf_journal_op_id_lru_balance_update_last,
	ocf_journal_op_id_lru_balance_set_hot,
	ocf_journal_op_id_lru_add,
	ocf_journal_op_id_lru_add_insert,
	ocf_journal_op_set_part,
	ocf_journal_op_id_lru_clean_update,
	ocf_journal_op_id_lru_set_hot,
	ocf_journal_op_id_count
};

#define OCF_JOURNAL_MAX_SUB_OPS 4

typedef void (*ocf_journal_rollback_cb)(ocf_cache_t cache, ocf_jop_t op);

struct ocf_journal_schema
{
	enum ocf_journal_op_id sub_ops[ocf_journal_op_id_count]
			[OCF_JOURNAL_MAX_SUB_OPS];
	unsigned sub_op_count[ocf_journal_op_id_count];
	ocf_journal_rollback_cb rollback_cb[ocf_journal_op_id_count];
};

#include "utils_journal_priv.h"

/* transaction operation structure declaration */
#define declare_sub_ops(s, op, ...) ({ \
		unsigned _i; \
		enum ocf_journal_op_id _t[OCF_JOURNAL_MAX_SUB_OPS + 1] = { \
				__VA_ARGS__}; \
		_i = 0; \
		s->sub_op_count[op] = 0; \
		while (_t[_i] != 0) { \
			s->sub_ops[op][_i]= _t[_i]; \
			s->sub_op_count[op]++; \
			_i++; \
		} \
	})

#define declare_rollback_cb(s, op, cb) s->rollback_cb[op] = cb;

/* management api */
int ocf_journal_init(ocf_cache_t cache, struct ocf_journal_schema *schema,
		void *buf, size_t buf_size,
		ocf_journal_t *jrnl);
void ocf_journal_deinit(ocf_journal_t j);
void ocf_journal_start(ocf_journal_t jrnl);

void ocf_journal_schema_init(struct ocf_journal_schema *schema);

/* transaction api */
ocf_jop_t ocf_journal_start_transaction(ocf_journal_t j,
		enum ocf_journal_op_id op_id);
void ocf_journal_finish_transaction(ocf_journal_t j,
		ocf_jop_t op);

/* operation api */
ocf_jop_t ocf_journal_start_op(ocf_jop_t op,
		enum ocf_journal_op_id op_id);

ocf_jop_t ocf_journal_finish_op(ocf_jop_t op);


#define OCF_JOURNAL_SET_DATA(...) (op ? ({ \
		struct ocf_jdata _data = {__VA_ARGS__}; \
		ocf_journal_get_next(op)->data = _data; \
		op; }) : NULL )

/* if op != NULL then we are running in a context of larger transaction and
 * the space is already allocated in the journal. */
#define OCF_JOURNAL_TRANSACTION_START(j, op_id, ...) \
		op = (j && !op) ? ocf_journal_start_transaction(j, op_id) : op;

#define OCF_JOURNAL_TRANSACTION_END(j) ({ \
	if (j && op->parent == 0) \
		ocf_journal_finish_transaction(j, op); \
	})

#define OCF_JOURNAL_START(op_id, ...) ({ \
		OCF_JOURNAL_SET_DATA(__VA_ARGS__); \
		op = ocf_journal_start_op(op, op_id); \
	})

#define OCF_JOURNAL_NEXT(...) ({ \
		OCF_JOURNAL_END(); \
		OCF_JOURNAL_START(__VA_ARGS__); \
	})

#define OCF_JOURNAL_START_SWAP(op_id, _old, _new) \
		OCF_JOURNAL_START(op_id, .swap.old = _old, .swap.new = _new)

#define OCF_JOURNAL_NEXT_SWAP(op_id, _old, _new) ({ \
		OCF_JOURNAL_END(); \
		OCF_JOURNAL_START_SWAP(op_id, _old, _new); \
	})

#define OCF_JOURNAL_END() ({op = ocf_journal_finish_op(op);})

/* revcovery */
int ocf_journal_recover(ocf_cache_t cache, ocf_journal_t j);
