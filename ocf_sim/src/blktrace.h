/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _BLKTRACE_H_
#define	_BLKTRACE_H_

#define	BLKTRACE_TS(_ts)	((_ts).ts)	// The scheduler timestamp field in ocf_blktrace_ts_t
#define BLKTRACE_CRT(_ts)	((_ts).crt)	// The clock_realtime field in ocf_blktrace_ts_t

void blktrace_init(void);
void blktrace_set_path(char *path);
void blktrace_new(char *name);
void blktrace_cleanup(void);
#endif
