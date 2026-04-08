/*
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_ENV_H__
#define __OCF_ENV_H__

/*
 * Default posix environment configuration.
 *
 * Each section in ocf_env_default.h is guarded by an OCF_ENV_POSIX_*
 * define. To replace a section with a custom implementation, remove the
 * corresponding define below and provide your own definitions.
 */

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
#define OCF_ENV_POSIX_TIME
#define OCF_ENV_POSIX_SORTING
#define OCF_ENV_POSIX_CRC
#define OCF_ENV_POSIX_EXECUTION_CONTEXT

#include "ocf_env_default.h"

#endif /* __OCF_ENV_H__ */
