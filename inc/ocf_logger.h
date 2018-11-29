/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_LOGGER_H__
#define __OCF_LOGGER_H__

/**
 * @file
 * @brief Logger API
 */

#include <stdarg.h>

/**
 * @brief Verbosity levels of context log
 */
typedef enum {
	log_emerg,
	log_alert,
	log_crit,
	log_err,
	log_warn,
	log_notice,
	log_info,
	log_debug,
} ocf_logger_lvl_t;

struct ocf_logger {
	int (*open)(const struct ocf_logger *logger);
	void (*close)(const struct ocf_logger *logger);
	int (*printf)(const struct ocf_logger *logger, ocf_logger_lvl_t lvl,
			const char *fmt, va_list args);
	int (*printf_rl)(const char *func_name);
	int (*dump_stack)(const struct ocf_logger *logger);

	void *priv;
};

#endif /* __OCF_LOGGER_H__ */
