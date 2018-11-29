/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_env.h"
#include "ocf/ocf_logger.h"
#include "ocf_logger_priv.h"

/*
 *
 */
__attribute__((format(printf, 3, 4)))
int ocf_log_raw(const struct ocf_logger *logger, ocf_logger_lvl_t lvl,
		const char *fmt, ...)
{
	va_list args;
	int ret;

	if (!logger->printf)
		return -ENOTSUP;

	va_start(args, fmt);
	ret = logger->printf(logger, lvl, fmt, args);
	va_end(args);

	return ret;
}

int ocf_log_raw_rl(const struct ocf_logger *logger, const char *func_name)
{
	if (!logger->printf_rl)
		return -ENOTSUP;

	return logger->printf_rl(func_name);
}

/*
 *
 */
int ocf_log_stack_trace_raw(const struct ocf_logger *logger)
{
	return !logger->dump_stack ? -ENOTSUP :
			logger->dump_stack(logger);
}
