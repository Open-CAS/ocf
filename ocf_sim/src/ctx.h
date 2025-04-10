/*
 * Copyright(c) 2019-2021 Intel Corporation
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __CTX_H__
#define __CTX_H__

#include <time.h>

#include <ocf/ocf.h>
#include "scheduler.h"

#define MAX_LENGTH_PTHREAD_NAME (16)
#define BILLION  1000000000ULL

#define SEC(_sec)		((uint64_t)(_sec) * 1000000000)
#define MSEC(_msec)		((uint64_t)(_msec) * 1000000)
#define USEC(_usec)		((uint64_t)(_usec) * 1000)


ctx_data_t *ocf_ctx_data_alloc1(uint32_t pages);
void ocf_ctx_data_free1(ctx_data_t* ctx_data);
int ctx_init(ocf_ctx_t* ocf_ctx);
void ctx_cleanup(ocf_ctx_t ctx);

static inline uint64_t clock_realtime(void)
{
       struct timespec ts;

       return clock_gettime(CLOCK_REALTIME, &ts) ? 0 : (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
}

/*
 * Helper macro for error handling.
 */
#define	error(_msg)									\
	do {										\
		printf("ERROR: %s:%d(%s) - %s\n", __FILE__, __LINE__, __func__, _msg);	\
		exit(1);								\
	} while (0)

#define	error1(_fmt, ...)									\
	do {										\
		printf("ERROR: %s:%d(%s) - " _fmt "\n", __FILE__, __LINE__, __func__, __VA_ARGS__);	\
		exit(1);								\
	} while (0)

extern uint8_t verbose;
extern uint64_t backend_vol_sz, cache_vol_sz, top_msla_vol_sz;

#define ocf_log(lvl, fmt, ...)	do {							\
	if (verbose >= lvl) {								\
		char buf[MAX_LENGTH_PTHREAD_NAME];					\
		pthread_getname_np(pthread_self(), buf, MAX_LENGTH_PTHREAD_NAME);	\
		printf("%s " fmt, buf, __VA_ARGS__); 					\
	} } while (0)


#define ocf_log_timestamp(lvl, fmt, ...)	do {					\
	if (verbose >= lvl) {								\
		char buf[MAX_LENGTH_PTHREAD_NAME];					\
		scheduler_t s = scheduler_get_instance();				\
		uint64_t ts = scheduler_get_current_time(s, NULL);			\
		pthread_getname_np(pthread_self(), buf, MAX_LENGTH_PTHREAD_NAME);	\
		printf("%s %lu " fmt, buf, ts, __VA_ARGS__); 				\
	}} while (0)

#define ocf_log_time(lvl, fmt, ...)							\
	if (verbose >= lvl) do {							\
		time_t ltime = time(NULL);						\
		struct tm ctime;							\
		char stime[32];								\
		localtime_r(&ltime, &ctime);						\
		strftime(stime, sizeof(stime), "%Y-%m-%d %T", &ctime);			\
		ocf_log(lvl, "%s - " fmt, stime __VA_OPT__(, ) __VA_ARGS__);		\
	} while (0)

#endif
