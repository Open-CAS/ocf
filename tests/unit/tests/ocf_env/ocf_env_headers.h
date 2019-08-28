/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

/**
 * @file
 * @brief OCF libs and macros
 *
* This file is mostly to aggregate external header includes.
 */
#ifndef __OCF_ENV_HEADERS_H__
#define __OCF_ENV_HEADERS_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* TODO: Move prefix printing to context logger. */
#define OCF_LOGO ""
#define OCF_PREFIX_SHORT "[" OCF_LOGO "] "
#define OCF_PREFIX_LONG "Open CAS Framework"

#define OCF_VERSION_MAIN 1
#define OCF_VERSION_MAJOR 1
#define OCF_VERSION_MINOR 1

#endif /* __OCF_ENV_HEADERS_H__ */
