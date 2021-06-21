/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "ocf_env.h"
#include "utils_journal.h"
#include "../eviction/lru_transaction_schema.h"

static inline void mark_started(ocf_jop_t op)
{
	env_smp_wmb();
	op->started = true;
	env_smp_wmb();
}

static inline void clear_started(ocf_jop_t op)
{
	env_smp_wmb();
	op->started = false;
	env_smp_wmb();
}

static inline bool is_started(ocf_jop_t op)
{
	bool ret;

	env_smp_rmb();
	ret = op->started;
	env_smp_rmb();

	return ret;
}
static inline void mark_finished(ocf_jop_t op)
{
	env_smp_wmb();
	op->finished = true;
	env_smp_wmb();
}

static inline void clear_finished(ocf_jop_t op)
{
	env_smp_wmb();
	op->finished = false;
	env_smp_wmb();
}

static inline bool is_finished(ocf_jop_t op)
{
	bool ret;

	env_smp_rmb();
	ret = op->finished;
	env_smp_rmb();

	return ret;
}

static inline ocf_jop_t get_op_by_idx(ocf_jop_t op,
		int idx)
{
	ocf_jop_t ring_buff = op - op->ring_idx;
	int req_idx;

	req_idx = (op->ring_idx + idx) % op->ring_capacity;

	/* workaround for C modulo returning negative values */
	req_idx = (req_idx >= 0) ? req_idx : req_idx + op->ring_capacity;

	return &ring_buff[req_idx];
}

static unsigned _ocf_journal_schema_dfs(struct ocf_journal_schema *schema,
		enum ocf_journal_op_id op_id, unsigned cnt,
		ocf_journal_schema_dfs_cb_t cb, void *ctx)
{
	int c = cnt;
	int i;

	if (cb)
		cb(schema, op_id, c, ctx);

	for (i = 0; i < schema->sub_op_count[op_id]; i++) {
		c = _ocf_journal_schema_dfs(schema, schema->sub_ops[op_id][i], c + 1,
				cb, ctx);
	}

	return c;
}

static unsigned ocf_journal_schema_dfs(struct ocf_journal_schema *schema,
		enum ocf_journal_op_id op_id,
		ocf_journal_schema_dfs_cb_t cb, void *ctx)
{
	return _ocf_journal_schema_dfs(schema, op_id, 0, cb, ctx);
}

static unsigned ocf_journal_get_op_count(struct ocf_journal_schema *schema,
		enum ocf_journal_op_id op_id)
{

	return ocf_journal_schema_dfs(schema, op_id, NULL, NULL) + 1;
}

static bool ocf_journal_alloc_space(ocf_journal_t jrnl,
		uint32_t count, ocf_journal_idx_t *pos)
{
	struct ocf_journal_ring *ring = &jrnl->ring;
	unsigned capacity = ring->hdr->capacity;
	uint32_t started_idx, finished_idx, free;

	ENV_BUG_ON(count == 0);

	env_mutex_lock(&jrnl->mutex);

	if (ring->hdr->full || capacity < count) {
		env_mutex_unlock(&jrnl->mutex);
		return false;
	}

	started_idx = ring->hdr->started_idx;
	finished_idx = ring->hdr->finished_idx;

	free = started_idx >= finished_idx ?
		capacity - (started_idx - finished_idx) :
		finished_idx - started_idx;

	if (free < count) {
		env_mutex_unlock(&jrnl->mutex);
		return false;
	}

	*pos = started_idx;
	started_idx = (started_idx + count) % capacity;
	if (started_idx == finished_idx) {
		ring->hdr->full = true;
		env_smp_wmb();
	}
	ring->hdr->started_idx = started_idx;
	env_smp_wmb();

	env_mutex_unlock(&jrnl->mutex);

	return true;
}

static inline void ocf_jurnal_clear_op(ocf_jop_t op)
{
	env_smp_wmb();
	op->id = ocf_journal_op_id_lru_invalid;
	env_smp_wmb();
	op->started = false;
	op->finished = false;
	env_smp_wmb();
}

static void ocf_journal_free_space(ocf_journal_t jrnl, ocf_journal_idx_t pos)
{
	struct ocf_journal_ring *ring = &jrnl->ring;

	ENV_BUG_ON(!is_finished(&ring->buff[pos]));

	env_mutex_lock(&jrnl->mutex);
	if (ring->hdr->finished_idx == pos) {
		while (is_finished(&ring->buff[pos])) {
			ocf_jurnal_clear_op(&ring->buff[pos]);
			pos = (pos + 1) % ring->hdr->capacity;
		}
		ring->hdr->finished_idx = pos;
		if (ring->hdr->full) {
			env_smp_wmb();
			ring->hdr->full = false;
		}
	}
	env_mutex_unlock(&jrnl->mutex);
}

static void ocf_journal_rollback_op(ocf_cache_t cache, ocf_journal_t jrnl,
		ocf_jop_t op)
{
	struct ocf_journal_schema *schema = jrnl->schema;
	ocf_journal_rollback_cb rollback;
	ocf_jop_t child;
	ocf_journal_idx_t next;
	ocf_journal_idx_t children_idx[OCF_JOURNAL_MAX_SUB_OPS];
	int i;

	if (!is_started(op))
		return;

	rollback = schema->rollback_cb[op->id];

#if 0
	/* TODO: in case of concurrent metadata accesses composite operations
	 *  might need to provide a rollback function of their own since
	 *  sub-ops data is stale after releasing a mutex. However if composite
	 *  ops rollback function is used, extra mechanisms must be implemented
	 *  to assure rollback operation is crash-safe.
	 */
	if (is_finished(op)) {
		rollback = schema->rollback_cb[op_id];
		if (rollback) {
			rollback(cache, op);
			clear_finished(op);
			clear_started(op);
			return;
		}
	}
#else
	if (rollback) {
		clear_finished(op);
		rollback(cache, op);
		clear_started(op);
		return;
	}
#endif

	ENV_BUG_ON(schema->sub_op_count[op->id] == 0);

	/* calculate children indexes to visit them in reverse order */
	next = 1;
	for (i = 0; i < schema->sub_op_count[op->id]; i++) {
		children_idx[i] = next;
		child = get_op_by_idx(op, next);
		next += ocf_journal_get_op_count(jrnl->schema, child->id);
	}

	/* rollback child operations in reverse order */
	for (i = schema->sub_op_count[op->id]; i >= 0; i--) {
		child = get_op_by_idx(op, children_idx[i]);
		ocf_journal_rollback_op(cache, jrnl, child);
	}
}

void ocf_journal_rollback(ocf_cache_t cache, ocf_journal_t jrnl)
{
	ocf_journal_idx_t pos = jrnl->ring.hdr->started_idx;
	ocf_journal_idx_t end = jrnl->ring.hdr->finished_idx;
	ocf_jop_t op ;

	while (pos != end || jrnl->ring.hdr->full) {
		op = &jrnl->ring.buff[pos];
		if (is_started(op))
			ocf_journal_rollback_op(cache, jrnl, op);
		ocf_journal_free_space(jrnl, op->ring_idx);

		ENV_BUG_ON(pos == jrnl->ring.hdr->started_idx);
		pos = jrnl->ring.hdr->started_idx;
	}

}


#if OCF_JOURNAL_DEBUG
struct ocf_journal_debug_params
{
	struct {
		ocf_jop_t parent;
		enum ocf_journal_op_id op_id;
	} start_params;

	bool new_found;
};

void ocf_journal_start_debug_cb(struct ocf_journal_schema *schema,
	enum ocf_journal_op_id op_id, unsigned cnt, void *ctx)
{
	struct ocf_journal_debug_params *params = ctx;
	ocf_jop_t curr;

	curr = get_op_by_idx(params->start_params.parent, cnt);

	if (params->new_found) {
		ENV_BUG_ON(is_started(curr));
		return;
	}

	if (!is_started(curr)) {
		params->new_found = true;
		ENV_BUG_ON(op_id != params->start_params.op_id);
	} else {
		ENV_BUG_ON(curr->id != op_id);
		if (curr != params->start_params.parent)
			ENV_BUG_ON(!is_finished(curr));
		else
			ENV_BUG_ON(is_finished(curr));
	}
}

void ocf_journal_start_debug_check(ocf_jop_t op,
		enum ocf_journal_op_id op_id)
{
	struct ocf_journal_debug_params params = {
		.start_params = {
			.parent = op,
			.op_id = op_id
		},
		.new_found = false
	};

	ENV_BUG_ON(!is_started(op));
	ENV_BUG_ON(is_finished(op));
	ocf_journal_schema_dfs(op->jrnl->schema, op->id, ocf_journal_start_debug_cb,
			&params);
}
#endif

ocf_jop_t ocf_journal_start_op(ocf_jop_t op,
		enum ocf_journal_op_id op_id)
{
	long parent;
	ocf_jop_t child;

	if (!op)
		return NULL;

	if (!is_started(op)) {
		/* first op in transaction */
		ENV_BUG_ON(op->parent != 0);
		mark_started(op);
		return op;
	}

	child = ocf_journal_get_next(op);
	parent = op - child;
	child->ring_capacity = op->ring_capacity;
	child->desc_visited = 0;
	child->parent = (parent >= 0) ? parent : parent + op->ring_capacity;
	child->ring_idx = (op->ring_idx + (child - op)) % op->ring_capacity;
	child->id = op_id;

#if OCF_JOURNAL_DEBUG
	child->jrnl = op->jrnl;
	ocf_journal_start_debug_check(op, op_id);
#endif


	mark_started(child);

	return child;
}

#if OCF_JOURNAL_DEBUG

void ocf_journal_finish_debug_cb(struct ocf_journal_schema *schema,
	enum ocf_journal_op_id op_id, unsigned cnt, void *ctx)
{
	ocf_jop_t finished_op = ctx;
	ocf_jop_t curr_op = get_op_by_idx(finished_op, cnt);

	if (curr_op == finished_op) {
		ENV_BUG_ON(!is_started(curr_op));
		ENV_BUG_ON(is_finished(curr_op));
	 } else {
		 /* possible to have a successor op not started (skipped) */
		 ENV_BUG_ON(is_finished(curr_op) != is_started(curr_op));
	}

	ENV_BUG_ON(curr_op->id != op_id);
}

void ocf_journal_finish_debug_check(ocf_jop_t op)
{
	ocf_journal_schema_dfs(op->jrnl->schema, op->id,
			ocf_journal_finish_debug_cb, op);
}
#endif

ocf_jop_t ocf_journal_finish_op(ocf_jop_t op)
{
	ocf_jop_t parent;

	if (!op)
		return NULL;

	parent = get_op_by_idx(op, op->parent);

#if OCF_JOURNAL_DEBUG
	ocf_journal_finish_debug_check(op);
#endif

	parent->desc_visited += op->desc_visited + 1;

	mark_finished(op);

	/* parent will be null for transaction head */
	return parent ?: op;
}

ocf_jop_t ocf_journal_start_transaction(ocf_journal_t jrnl,
		enum ocf_journal_op_id op_id)
{
	unsigned op_count = ocf_journal_get_op_count(jrnl->schema, op_id);
	ocf_jop_t op;
	ocf_journal_idx_t pos;

	if (!ocf_journal_alloc_space(jrnl, op_count, &pos)) {
		ENV_BUG_ON(1);
		return NULL;
	}

	op = &jrnl->ring.buff[pos];

	op->parent = 0;
	op->desc_visited = 0;
	op->ring_idx = pos;
	op->ring_capacity = jrnl->ring.hdr->capacity;
	op->id = op_id;
#if OCF_JOURNAL_DEBUG
	op->jrnl = jrnl;
#endif

	return op;
}

void ocf_journal_finish_transaction(ocf_journal_t jrnl,
		ocf_jop_t op)
{
	ENV_BUG_ON(!is_started(op));
	ENV_BUG_ON(!is_finished(op));
	ENV_BUG_ON(op->parent != 0);

	ocf_journal_free_space(jrnl, op->ring_idx);
}

ocf_jop_t ocf_journal_get_next(ocf_jop_t op)
{
	return is_started(op) ? get_op_by_idx(op, op->desc_visited + 1) : op;
}


static inline size_t ocf_journal_capacity(size_t buf_size)
{
	size_t item_size = sizeof(struct ocf_journal_op);
	size_t hdr_size = sizeof(struct ocf_journal_hdr);

	return (buf_size - hdr_size) / item_size;
}

void ocf_journal_start(ocf_journal_t jrnl)
{
	struct ocf_journal_hdr *hdr = jrnl->ring.hdr;

	ENV_BUG_ON(hdr->initialized && hdr->started_idx != hdr->finished_idx);

	hdr->capacity = ocf_journal_capacity(jrnl->buf_size);
	hdr->started_idx = 0;
	hdr->finished_idx = 0;
	hdr->full = false;
	env_smp_wmb();
	hdr->initialized = true;
}

int ocf_journal_recover(ocf_cache_t cache, ocf_journal_t jrnl)
{
	if (!jrnl->ring.hdr->initialized) {
		/* looks like OCF crash before journal was initialized */
		ocf_journal_start(jrnl);
		return 0;
	}

	if (jrnl->ring.hdr->started_idx != jrnl->ring.hdr->finished_idx &&
		       jrnl->ring.hdr->full) {
		/* should only happen in case of crash during allocation */
		jrnl->ring.hdr->full = false;
	}

	/* check for current journal buffer size mismatch vs the capacity stored
	 * in journal buffer */
	ENV_BUG_ON(ocf_journal_capacity(jrnl->buf_size)  !=
			jrnl->ring.hdr->capacity);

	ocf_journal_rollback(cache, jrnl);

	return 0;
}

int ocf_journal_init(ocf_cache_t cache, struct ocf_journal_schema *schema,
		void *buf, size_t buf_size,
		ocf_journal_t *jrnl)
{
	uint32_t size = buf_size;
	ocf_journal_t tmp;
	size_t capacity;

	if (size <= sizeof(struct ocf_journal_hdr)) {
		return -EINVAL;
	}

	tmp = env_vzalloc(sizeof(*tmp));
	if (!tmp)
		return -OCF_ERR_NO_MEM;

	tmp->schema = schema;

	capacity = ocf_journal_capacity(buf_size);
	ENV_BUG_ON(2ULL << (sizeof(tmp->ring.hdr->started_idx) * 8) <= capacity);

	tmp->ring.hdr = buf;
	tmp->ring.buff = &tmp->ring.hdr->ring[0];
	tmp->buf_size = buf_size;

	*jrnl = tmp;
	return 0;
}

void ocf_journal_deinit(ocf_journal_t jrnl)
{
	if (!jrnl)
		return;

	jrnl->ring.hdr->initialized = false;
	env_vfree(jrnl);
}

void ocf_journal_schema_init(struct ocf_journal_schema *schema)
{
	ocf_lru_transaction_schema_init(schema);
}
ocf_jop_t ocf_journal_op_get_parent(ocf_jop_t op)
{
	return get_op_by_idx(op, op->parent);
}
