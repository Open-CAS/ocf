/*
 * Copyright(c) 2019-2021 Intel Corporation
 * Copyright(c) 2024-2025 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_ENV_REFCNT_H__
#define __OCF_ENV_REFCNT_H__

#include "ocf_env.h"

typedef void (*env_refcnt_cb_t)(void *priv);

struct env_refcnt
{
	env_atomic counter __attribute__((aligned(64)));
	env_atomic freeze;
	env_atomic callback;
	env_refcnt_cb_t cb;
	void *priv;
};

/* Initialize reference counter */
int env_refcnt_init(struct env_refcnt *rc, const char *name, size_t name_len);

void env_refcnt_deinit(struct env_refcnt *rc);

/* Try to increment counter. Returns true if successfull, false
 * if counter is frozen */
bool env_refcnt_inc(struct env_refcnt  *rc);

/* Decrement reference counter */
void env_refcnt_dec(struct env_refcnt *rc);

/* Disallow incrementing of underlying counter - attempts to increment counter
 * will be failing until env_refcnt_unfreeze is calleed.
 * It's ok to call freeze multiple times, in which case counter is frozen
 * until all freeze calls are offset by a corresponding unfreeze.*/
void env_refcnt_freeze(struct env_refcnt *rc);

/* Cancel the effect of single env_refcnt_freeze call */
void env_refcnt_unfreeze(struct env_refcnt *rc);

bool env_refcnt_frozen(struct env_refcnt *rc);

bool env_refcnt_zeroed(struct env_refcnt *rc);

/* Register callback to be called when reference counter drops to 0.
 * Must be called after counter is frozen.
 * Cannot be called until previously regsitered callback had fired. */
void env_refcnt_register_zero_cb(struct env_refcnt *rc, env_refcnt_cb_t cb,
		void *priv);

#endif // __OCF_ENV_REFCNT_H__
