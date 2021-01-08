/*
 * Copyright(c) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_seq_cutoff.h"
#include "ocf_cache_priv.h"
#include "ocf_priv.h"
#include "ocf/ocf_debug.h"
#include "utils/utils_cache_line.h"

#define SEQ_CUTOFF_FULL_MARGIN \
                (OCF_TO_EVICTION_MIN + OCF_PENDING_EVICTION_LIMIT)

static inline bool ocf_seq_cutoff_is_on(ocf_cache_t cache,
		struct ocf_request *req)
{
	if (!ocf_cache_is_device_attached(cache))
		return false;

	return (ocf_freelist_num_free(cache->freelist) <=
				SEQ_CUTOFF_FULL_MARGIN + req->core_line_count);
}

static int ocf_seq_cutoff_stream_cmp(struct ocf_rb_node *n1,
		struct ocf_rb_node *n2)
{
	struct ocf_seq_cutoff_stream *stream1 = container_of(n1,
			struct ocf_seq_cutoff_stream, node);
	struct ocf_seq_cutoff_stream *stream2 = container_of(n2,
			struct ocf_seq_cutoff_stream, node);

	if (stream1->rw < stream2->rw)
		return -1;

	if (stream1->rw > stream2->rw)
		return 1;

	if (stream1->last < stream2->last)
		return -1;

	if (stream1->last > stream2->last)
		return 1;

	return 0;
}

static struct ocf_rb_node *ocf_seq_cutoff_stream_list_find(
		struct list_head *node_list)
{
	struct ocf_seq_cutoff_stream *stream, *max_stream = NULL;
	struct ocf_rb_node *node;

	node = list_entry(node_list, struct ocf_rb_node, list);
	max_stream = container_of(node, struct ocf_seq_cutoff_stream, node);
	list_for_each_entry(node, node_list, list) {
		stream = container_of(node, struct ocf_seq_cutoff_stream, node);
		if (stream->bytes > max_stream->bytes)
			max_stream = stream;
	}

	return &max_stream->node;
}

int ocf_core_seq_cutoff_init(ocf_core_t core)
{
	struct ocf_seq_cutoff_stream *stream;
	int i;

	ocf_core_log(core, log_info, "Seqential cutoff init\n");

	core->seq_cutoff = env_vmalloc(sizeof(*core->seq_cutoff));
	if (!core->seq_cutoff)
		return -OCF_ERR_NO_MEM;

	env_rwlock_init(&core->seq_cutoff->lock);
	ocf_rb_tree_init(&core->seq_cutoff->tree, ocf_seq_cutoff_stream_cmp,
			ocf_seq_cutoff_stream_list_find);
	INIT_LIST_HEAD(&core->seq_cutoff->lru);

	for (i = 0; i < OCF_SEQ_CUTOFF_MAX_STREAMS; i++) {
		stream = &core->seq_cutoff->streams[i];
		stream->last = 4096 * i;
		stream->bytes = 0;
		stream->rw = 0;
		ocf_rb_tree_insert(&core->seq_cutoff->tree, &stream->node);
		list_add_tail(&stream->list, &core->seq_cutoff->lru);
	}

	return 0;
}

void ocf_core_seq_cutoff_deinit(ocf_core_t core)
{
	env_rwlock_destroy(&core->seq_cutoff->lock);
	env_vfree(core->seq_cutoff);
}

void ocf_dbg_get_seq_cutoff_status(ocf_core_t core,
		struct ocf_dbg_seq_cutoff_status *status)
{
	struct ocf_seq_cutoff_stream *stream;
	uint32_t threshold;
	int i = 0;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(status);

	threshold = ocf_core_get_seq_cutoff_threshold(core);

	env_rwlock_read_lock(&core->seq_cutoff->lock);
	list_for_each_entry(stream, &core->seq_cutoff->lru, list) {
		status->streams[i].last = stream->last;
		status->streams[i].bytes = stream->bytes;
		status->streams[i].rw = stream->rw;
		status->streams[i].active = (stream->bytes >= threshold);
		i++;
	}
	env_rwlock_read_unlock(&core->seq_cutoff->lock);
}

bool ocf_core_seq_cutoff_check(ocf_core_t core, struct ocf_request *req)
{
	ocf_seq_cutoff_policy policy = ocf_core_get_seq_cutoff_policy(core);
	uint32_t threshold = ocf_core_get_seq_cutoff_threshold(core);
	ocf_cache_t cache = ocf_core_get_cache(core);
	struct ocf_seq_cutoff_stream item = {
		.last = req->byte_position, .rw = req->rw
	};
	struct ocf_seq_cutoff_stream *stream;
	struct ocf_rb_node *node;
	bool result = false;

	switch (policy) {
		case ocf_seq_cutoff_policy_always:
			break;
		case ocf_seq_cutoff_policy_full:
			if (ocf_seq_cutoff_is_on(cache, req))
				break;
			return false;

		case ocf_seq_cutoff_policy_never:
			return false;
		default:
			ENV_WARN(true, "Invalid sequential cutoff policy!");
			return false;
	}

	env_rwlock_read_lock(&core->seq_cutoff->lock);
	node = ocf_rb_tree_find(&core->seq_cutoff->tree, &item.node);
	if (node) {
		stream = container_of(node, struct ocf_seq_cutoff_stream, node);
		if (stream->bytes + req->byte_length >= threshold)
			result = true;
	}
	env_rwlock_read_unlock(&core->seq_cutoff->lock);

	return result;
}

void ocf_core_seq_cutoff_update(ocf_core_t core, struct ocf_request *req)
{
	ocf_seq_cutoff_policy policy = ocf_core_get_seq_cutoff_policy(core);
	struct ocf_seq_cutoff_stream item = {
		.last = req->byte_position, .rw = req->rw
	};
	struct ocf_seq_cutoff_stream *stream;
	struct ocf_rb_node *node;
	bool can_update;

	if (policy == ocf_seq_cutoff_policy_never)
		return;

	/* Update last accessed position and bytes counter */
	env_rwlock_write_lock(&core->seq_cutoff->lock);
	node = ocf_rb_tree_find(&core->seq_cutoff->tree, &item.node);
	if (node) {
		stream = container_of(node, struct ocf_seq_cutoff_stream, node);
		item.last = req->byte_position + req->byte_length;
		can_update = ocf_rb_tree_can_update(&core->seq_cutoff->tree,
				node, &item.node);
		stream->last = req->byte_position + req->byte_length;
		stream->bytes += req->byte_length;
		if (!can_update) {
			ocf_rb_tree_remove(&core->seq_cutoff->tree, node);
			ocf_rb_tree_insert(&core->seq_cutoff->tree, node);
		}
		list_move_tail(&stream->list, &core->seq_cutoff->lru);
	} else {
		stream = list_first_entry(&core->seq_cutoff->lru,
				struct ocf_seq_cutoff_stream, list);
		ocf_rb_tree_remove(&core->seq_cutoff->tree, &stream->node);
		stream->rw = req->rw;
		stream->last = req->byte_position + req->byte_length;
		stream->bytes = req->byte_length;
		ocf_rb_tree_insert(&core->seq_cutoff->tree, &stream->node);
		list_move_tail(&stream->list, &core->seq_cutoff->lru);
	}
	env_rwlock_write_unlock(&core->seq_cutoff->lock);
}
