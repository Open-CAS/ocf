/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_LOGGER_PRIV_H__
#define __OCF_LOGGER_PRIV_H__

__attribute__((format(printf, 3, 4)))
int ocf_log_raw(const struct ocf_logger *logger, ocf_logger_lvl_t lvl,
		const char *fmt, ...);

int ocf_log_raw_rl(const struct ocf_logger *logger, const char *func_name);

int ocf_log_stack_trace_raw(const struct ocf_logger *logger);


#endif /* __OCF_LOGGER_PRIV_H__ */
