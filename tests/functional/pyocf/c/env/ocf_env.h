/*
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Custom ocf_env.h for pyocf test environment.
 *
 * Replaces OCF_ENV_POSIX_TIME with a custom implementation that supports
 * controllable time offset for testing.
 */

#ifndef __OCF_ENV_H__
#define __OCF_ENV_H__

#define OCF_ENV_POSIX_DEBUG
#define OCF_ENV_POSIX_STRING
#define OCF_ENV_POSIX_MEMORY
#define OCF_ENV_POSIX_MUTEX
#define OCF_ENV_POSIX_RMUTEX
#define OCF_ENV_POSIX_RWSEM
#define OCF_ENV_POSIX_COMPLETION
#define OCF_ENV_POSIX_ATOMIC
#define OCF_ENV_POSIX_SPINLOCK
#define OCF_ENV_POSIX_RWLOCK
#define OCF_ENV_POSIX_BIT
#define OCF_ENV_POSIX_SCHEDULING
/* OCF_ENV_POSIX_TIME intentionally not defined - using custom impl */
#define OCF_ENV_POSIX_SORTING
#define OCF_ENV_POSIX_CRC
#define OCF_ENV_POSIX_EXECUTION_CONTEXT

#include "ocf_env_default.h"

#include "ocf_env_time.h"

#endif /* __OCF_ENV_H__ */
