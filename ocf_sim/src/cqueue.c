/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cqueue.h"

CQueueHead* cqueue_create(void)
{
	CQueueHead* handle = malloc(sizeof(CQueueHead));
	handle->head = NULL;
	handle->tail = NULL;
	handle->len = 0;

	pthread_mutex_t* lock = malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init(lock, NULL);
	handle->lock = lock;

	return handle;
}

void cqueue_destroy(CQueueHead* handle)
{
	pthread_mutex_destroy(handle->lock);
	free(handle->lock);
	free(handle);
}

void cqueue_push(CQueueHead* handle, void* value)
{
	CQueueItem* new_item_p = (CQueueItem*)value;
	new_item_p->next = NULL;

	pthread_mutex_lock(handle->lock);
	if (!handle->head) {
		handle->head = new_item_p;
		handle->tail = new_item_p;
	}
	else {
		handle->tail->next = new_item_p;
		handle->tail = new_item_p;
	}
	handle->len++;
	pthread_mutex_unlock(handle->lock);
}

void* cqueue_pop(CQueueHead* handle)
{
	CQueueItem* item_copy_p;
	if (!handle->head) {
		return NULL;
	}

	pthread_mutex_lock(handle->lock);
	if (handle->head) {
		item_copy_p = handle->head;
		handle->head = item_copy_p->next;
		handle->len--;
	} else {
		item_copy_p = NULL;
	}
	pthread_mutex_unlock(handle->lock);

	return item_copy_p;
}

uint64_t cqueue_len(CQueueHead* handle)
{
	return handle->len;
}
