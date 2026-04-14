/*
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Custom TIME section for pyocf test environment.
 *
 * Replaces the default posix env_get_tick_count with a fully test-controlled
 * counter. The "current time" is solely the value of ocf_env_tick_count_offset,
 * which tests advance explicitly. This makes time deterministic for cleaner
 * tests and avoids real-time drift between OCF time queries within a single
 * test.
 *
 * All other time functions (conversions, sleep) remain identical to the default
 * posix implementation.
 */

#ifndef __OCF_ENV_TIME_H__
#define __OCF_ENV_TIME_H__

#include <stdint.h>
#include <time.h>
#include <unistd.h>

#define ENV_SEC_TO_NSEC(_sec)	((_sec) * 1000000000)
#define ENV_NSEC_TO_SEC(_sec)	((_sec) / 1000000000)
#define ENV_NSEC_TO_MSEC(_sec)	((_sec) / 1000000)

extern uint64_t ocf_env_tick_count_offset;

static inline uint64_t env_get_tick_count(void)
{
	return ocf_env_tick_count_offset;
}

static inline uint64_t env_ticks_to_nsecs(uint64_t j)
{
	return j;
}

static inline uint64_t env_ticks_to_msecs(uint64_t j)
{
	return ENV_NSEC_TO_MSEC(j);
}

static inline uint64_t env_ticks_to_secs(uint64_t j)
{
	return ENV_NSEC_TO_SEC(j);
}

static inline uint64_t env_secs_to_ticks(uint64_t j)
{
	return ENV_SEC_TO_NSEC(j);
}

static inline void env_msleep(uint64_t n)
{
	usleep(n * 1000);
}

struct env_timeval {
	uint64_t sec, usec;
};

#endif /* __OCF_ENV_TIME_H__ */
