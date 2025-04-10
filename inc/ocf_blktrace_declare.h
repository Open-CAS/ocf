/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _OCF_BLKTRACE_DECLARE_H_
#define _OCF_BLKTRACE_DECLARE_H_

#include "ocf/ocf_types.h"

#ifdef OCF_BLKTRACE

typedef struct {
	uint64_t crt;	/* timespec.tv_sec * 1,000,000,000 + timespec.tv_nsec */
#ifdef OCF_SIM
	uint64_t ts;	/* OCF_SIM Scheduler timestamp */
#endif
} ocf_blktrace_ts_t;

typedef struct {
#ifdef OCF_SIM
	uint64_t signature;
#endif
	void *priv;			/* Reserved for the user (casadm/spdk/ocf_sim */
	ocf_blktrace_ts_t q_ts;		/* The Q timestamp */
	ocf_blktrace_ts_t last_ts;	/* The last timestamp */
} ocf_blktrace_io_t;

#define	OCF_BLKTRACE_DECLARE(_type, _var)		_type _var
#else

#define	OCF_BLKTRACE_DECLARE(_type, _var)
#endif

#endif	/* _OCF_BLKTRACE_DECLARE_H_ */
