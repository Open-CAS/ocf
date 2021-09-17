/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>
#include <pthread.h>

#include <ocf/ocf.h>
#include "queue_thread.h"

/* queue thread main function */
static void* run(void *);

/* helper class to store all synchronization related objects */
struct queue_thread
{
	/* thread running the queue */
	pthread_t thread;
	/* kick sets true, queue thread sets to false */
	bool signalled;
	/* request thread to exit */
	bool stop;
	/* conditional variable to sync queue thread and kick thread */
	pthread_cond_t cv;
	/* mutex for variables shared across threads */
	pthread_mutex_t mutex;
	/* associated OCF queue */
	struct ocf_queue *queue;
};

struct queue_thread *queue_thread_init(struct ocf_queue *q)
{
	struct queue_thread *qt = malloc(sizeof(*qt));
	int ret;

	if (!qt)
		return NULL;

	ret = pthread_cond_init(&qt->cv, NULL);
	if (ret)
		goto err_mem;

	ret = pthread_mutex_init(&qt->mutex, NULL);
	if (ret)
		goto err_cond;

	qt->signalled = false;
	qt->stop = false;
	qt->queue = q;

	ret = pthread_create(&qt->thread, NULL, run, qt);
	if (ret)
		goto err_mutex;

	return qt;

err_mutex:
	pthread_mutex_destroy(&qt->mutex);
err_cond:
	pthread_cond_destroy(&qt->cv);
err_mem:
	free(qt);

	return NULL;
}

void queue_thread_signal(struct queue_thread *qt, bool stop)
{
	pthread_mutex_lock(&qt->mutex);
	qt->signalled = true;
	qt->stop = stop;
	pthread_cond_signal(&qt->cv);
	pthread_mutex_unlock(&qt->mutex);
}

void queue_thread_destroy(struct queue_thread *qt)
{
	if (!qt)
		return;

	queue_thread_signal(qt, true);
	pthread_join(qt->thread, NULL);

	pthread_mutex_destroy(&qt->mutex);
	pthread_cond_destroy(&qt->cv);
	free(qt);
}

/* queue thread main function */
static void* run(void *arg)
{
	struct queue_thread *qt = arg;
	struct ocf_queue *q = qt->queue;

	pthread_mutex_lock(&qt->mutex);

	while (!qt->stop) {
		if (qt->signalled) {
			qt->signalled = false;
			pthread_mutex_unlock(&qt->mutex);

			/* execute items on the queue */
			ocf_queue_run(q);

			pthread_mutex_lock(&qt->mutex);
		}

		if (!qt->stop && !qt->signalled) 
			pthread_cond_wait(&qt->cv, &qt->mutex);
	}

	pthread_mutex_unlock(&qt->mutex);

	pthread_exit(0);
}

/* initialize I/O queue and management queue thread */
int initialize_threads(struct ocf_queue *mngt_queue, struct ocf_queue *io_queue)
{
	int ret = 0;

	struct queue_thread* mngt_queue_thread = queue_thread_init(mngt_queue);
	struct queue_thread* io_queue_thread = queue_thread_init(io_queue);

	if (!mngt_queue_thread || !io_queue_thread) {
		queue_thread_destroy(io_queue_thread);
		queue_thread_destroy(mngt_queue_thread);
		return 1;
	}

	ocf_queue_set_priv(mngt_queue, mngt_queue_thread);
	ocf_queue_set_priv(io_queue, io_queue_thread);

	return ret;
}

/* callback for OCF to kick the queue thread */
void queue_thread_kick(ocf_queue_t q)
{
	struct queue_thread *qt = ocf_queue_get_priv(q);

	queue_thread_signal(qt, false);
}

/* callback for OCF to stop the queue thread */
void queue_thread_stop(ocf_queue_t q)
{
	struct queue_thread *qt = ocf_queue_get_priv(q);

	queue_thread_destroy(qt);
}
