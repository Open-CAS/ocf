/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CQUEUE_H
#define CQUEUE_H

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct CQueueItem {
	void* next;
} CQueueItem;

typedef struct CQueueHead {
	CQueueItem* head;
	CQueueItem* tail;
	uint64_t len;
	pthread_mutex_t* lock;
} CQueueHead;

CQueueHead* cqueue_create(void);
void cqueue_destroy(CQueueHead* handle);
void cqueue_push(CQueueHead* handle, void* value);
void* cqueue_pop(CQueueHead* handle);
uint64_t cqueue_len(CQueueHead* handle);

#endif /* CQUEUE_H */
