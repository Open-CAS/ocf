/*
 * Copyright(c) 2020-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf_seq_detect.h"
#include "ocf_core_priv.h"
#include "ocf_queue_priv.h"
#include "ocf_request.h"
#include "ocf/ocf_debug.h"

static int ocf_seq_detect_stream_cmp(struct ocf_rb_node *n1,
		struct ocf_rb_node *n2)
{
	struct ocf_seq_detect_stream *s1 = container_of(n1,
			struct ocf_seq_detect_stream, node);
	struct ocf_seq_detect_stream *s2 = container_of(n2,
			struct ocf_seq_detect_stream, node);

	if (s1->valid < s2->valid)
		return -1;

	if (s1->valid > s2->valid)
		return 1;

	if (s1->rw < s2->rw)
		return -1;

	if (s1->rw > s2->rw)
		return 1;

	if (s1->last < s2->last)
		return -1;

	if (s1->last > s2->last)
		return 1;

	return 0;
}

static struct ocf_rb_node *ocf_seq_detect_stream_list_find(
		struct list_head *node_list)
{
	struct ocf_seq_detect_stream *stream, *max_stream = NULL;
	struct ocf_rb_node *node;

	node = list_entry(node_list, struct ocf_rb_node, list);
	stream = container_of(node, struct ocf_seq_detect_stream, node);
	list_for_each_entry(node, node_list, list) {
		stream = container_of(node, struct ocf_seq_detect_stream, node);
		if (!max_stream)
			max_stream = stream;
		if (stream->bytes > max_stream->bytes)
			max_stream = stream;
	}

	return max_stream ? &max_stream->node : NULL;
}

static void ocf_seq_detect_init(struct ocf_seq_detect *sd, int nstreams)
{
	struct ocf_seq_detect_stream *stream;
	int i;

	env_rwlock_init(&sd->lock);
	ocf_rb_tree_init(&sd->tree, ocf_seq_detect_stream_cmp,
			ocf_seq_detect_stream_list_find);
	INIT_LIST_HEAD(&sd->lru);
	env_atomic_set(&sd->consumer_count, 0);

	for (i = 0; i < nstreams; i++) {
		stream = &sd->streams[i];
		stream->last = 4096 * i;
		stream->bytes = 0;
		stream->rw = 0;
		stream->valid = false;
		ocf_rb_tree_insert(&sd->tree, &stream->node);
		list_add_tail(&stream->list, &sd->lru);
	}
}

static void ocf_seq_detect_deinit(struct ocf_seq_detect *sd)
{
	env_rwlock_destroy(&sd->lock);
}

int ocf_core_seq_detect_init(ocf_core_t core)
{
	core->seq_detect = env_vmalloc(sizeof(struct ocf_seq_detect_percore));
	if (!core->seq_detect)
		return -OCF_ERR_NO_MEM;

	ocf_seq_detect_init(core->seq_detect,
			OCF_SEQ_DETECT_PERCORE_STREAMS);

	return 0;
}

void ocf_core_seq_detect_deinit(ocf_core_t core)
{
	if (!core->seq_detect)
		return;

	ocf_seq_detect_deinit(core->seq_detect);
	env_vfree(core->seq_detect);
	core->seq_detect = NULL;
}

int ocf_queue_seq_detect_init(ocf_queue_t queue)
{
	queue->seq_detect = env_vmalloc(sizeof(struct ocf_seq_detect_perqueue));
	if (!queue->seq_detect)
		return -OCF_ERR_NO_MEM;

	ocf_seq_detect_init(queue->seq_detect,
			OCF_SEQ_DETECT_PERQUEUE_STREAMS);

	return 0;
}

void ocf_queue_seq_detect_deinit(ocf_queue_t queue)
{
	ocf_seq_detect_deinit(queue->seq_detect);
	env_vfree(queue->seq_detect);
}

void ocf_seq_detect_register_consumer(struct ocf_seq_detect *sd)
{
	env_atomic_inc(&sd->consumer_count);
}

void ocf_seq_detect_unregister_consumer(struct ocf_seq_detect *sd)
{
	env_atomic_dec(&sd->consumer_count);
}

static void ocf_seq_detect_sync_config(struct ocf_seq_detect *sd,
		ocf_core_t core)
{
	sd->promotion_count =
			ocf_core_get_seq_detect_promotion_count(core);
	sd->promotion_threshold =
			ocf_core_get_seq_detect_promotion_threshold(core);
}

static struct ocf_seq_detect_stream *ocf_seq_detect_update(
		struct ocf_seq_detect *sd,
		uint64_t addr, uint32_t len, int rw, bool insert)
{
	struct ocf_seq_detect_stream item = {
		.last = addr, .rw = rw, .valid = true
	};
	struct ocf_seq_detect_stream *stream;
	struct ocf_rb_node *node;
	bool can_update;

	node = ocf_rb_tree_find(&sd->tree, &item.node);
	if (node) {
		stream = container_of(node, struct ocf_seq_detect_stream, node);
		item.last = addr + len;
		can_update = ocf_rb_tree_can_update(&sd->tree,
				node, &item.node);
		stream->last = addr + len;
		stream->bytes += len;
		stream->req_count++;
		if (!can_update) {
			ocf_rb_tree_remove(&sd->tree, node);
			ocf_rb_tree_insert(&sd->tree, node);
		}
		list_move_tail(&stream->list, &sd->lru);

		return stream;
	}

	if (insert) {
		stream = list_first_entry(&sd->lru,
				struct ocf_seq_detect_stream, list);
		ocf_rb_tree_remove(&sd->tree, &stream->node);
		stream->rw = rw;
		stream->last = addr + len;
		stream->bytes = len;
		stream->req_count = 1;
		stream->valid = true;
		ocf_rb_tree_insert(&sd->tree, &stream->node);
		list_move_tail(&stream->list, &sd->lru);

		return stream;
	}

	return NULL;
}

static inline bool ocf_seq_detect_should_promote(
		struct ocf_seq_detect *sd,
		struct ocf_seq_detect_stream *stream)
{
	if (sd->promotion_threshold > 0
			&& stream->bytes >= sd->promotion_threshold)
		return true;

	if (stream->req_count >= sd->promotion_count)
		return true;

	return false;
}

static void ocf_seq_detect_promote(struct ocf_seq_detect *dst,
		struct ocf_seq_detect *src,
		struct ocf_seq_detect_stream *src_stream)
{
	struct ocf_seq_detect_stream *dst_stream;

	dst_stream = list_first_entry(&dst->lru,
			struct ocf_seq_detect_stream, list);
	ocf_rb_tree_remove(&dst->tree, &dst_stream->node);
	dst_stream->rw = src_stream->rw;
	dst_stream->last = src_stream->last;
	dst_stream->bytes = src_stream->bytes;
	dst_stream->req_count = src_stream->req_count;
	dst_stream->valid = true;
	ocf_rb_tree_insert(&dst->tree, &dst_stream->node);
	list_move_tail(&dst_stream->list, &dst->lru);
	src_stream->valid = false;
	list_move(&src_stream->list, &src->lru);
}

void ocf_core_seq_detect_update(ocf_core_t core, struct ocf_request *req)
{
	struct ocf_seq_detect *queue_sd = req->io_queue->seq_detect;
	struct ocf_seq_detect *core_sd = core->seq_detect;
	struct ocf_seq_detect_stream *stream;
	bool promote;

	if (env_atomic_read(&core_sd->consumer_count) == 0)
		return;

	/* Sync promotion config from persistent core metadata */
	ocf_seq_detect_sync_config(queue_sd, core);
	ocf_seq_detect_sync_config(core_sd, core);

	if (req->seq_cutoff_core) {
		env_rwlock_write_lock(&core_sd->lock);
		stream = ocf_seq_detect_update(core_sd,
				req->addr, req->bytes, req->rw, false);
		env_rwlock_write_unlock(&core_sd->lock);

		if (stream)
			return;
	}

	env_rwlock_write_lock(&queue_sd->lock);
	stream = ocf_seq_detect_update(queue_sd,
			req->addr, req->bytes, req->rw, true);
	promote = ocf_seq_detect_should_promote(queue_sd, stream);
	env_rwlock_write_unlock(&queue_sd->lock);

	if (promote) {
		env_rwlock_write_lock(&core_sd->lock);
		env_rwlock_write_lock(&queue_sd->lock);
		ocf_seq_detect_promote(core_sd, queue_sd, stream);
		env_rwlock_write_unlock(&queue_sd->lock);
		env_rwlock_write_unlock(&core_sd->lock);
	}
}

struct ocf_seq_detect_stream *ocf_seq_detect_find(
		struct ocf_seq_detect *sd, uint64_t addr, int rw)
{
	struct ocf_seq_detect_stream item = {
		.last = addr, .rw = rw, .valid = true
	};
	struct ocf_rb_node *node;

	node = ocf_rb_tree_find(&sd->tree, &item.node);
	if (!node)
		return NULL;

	return container_of(node, struct ocf_seq_detect_stream, node);
}

void ocf_dbg_get_seq_detect_status(ocf_core_t core,
		struct ocf_dbg_seq_detect_status *status)
{
	struct ocf_seq_detect_stream *stream;
	uint32_t threshold;
	int i = 0;

	OCF_CHECK_NULL(core);
	OCF_CHECK_NULL(status);

	threshold = ocf_core_get_seq_cutoff_threshold(core);

	env_rwlock_read_lock(&core->seq_detect->lock);
	list_for_each_entry(stream, &core->seq_detect->lru, list) {
		status->streams[i].last = stream->last;
		status->streams[i].bytes = stream->bytes;
		status->streams[i].rw = stream->rw;
		status->streams[i].active = (stream->bytes >= threshold);
		i++;
	}
	env_rwlock_read_unlock(&core->seq_detect->lock);
}
