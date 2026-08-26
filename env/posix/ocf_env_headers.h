/*
 * Copyright(c) 2019-2021 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_ENV_HEADERS_H__
#define __OCF_ENV_HEADERS_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* TODO: Move prefix printing to context logger. */
#define OCF_LOGO "OCF"
#define OCF_PREFIX_SHORT "[" OCF_LOGO "] "
#define OCF_PREFIX_LONG "Open CAS Framework"

#define ENV_ADAPTER_NAME "OCF Posix"
#define ENV_ADAPTER_VERSION_MAIN 20
#define ENV_ADAPTER_VERSION_MAJOR 3
#define ENV_ADAPTER_VERSION_MINOR 0

#endif /* __OCF_ENV_HEADERS_H__ */
