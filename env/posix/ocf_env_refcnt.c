/*
 * Copyright(c) 2019-2021 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf_env_refcnt.h"

int env_refcnt_init(struct env_refcnt *rc, const char *name, size_t name_len)
{
	env_atomic_set(&rc->counter, 0);
	env_atomic_set(&rc->freeze, 0);
	env_atomic_set(&rc->callback, 0);
	rc->cb = NULL;

	return 0;
}

void env_refcnt_deinit(struct env_refcnt *rc)
{

}

void env_refcnt_dec(struct env_refcnt *rc)
{
	int val = env_atomic_dec_return(&rc->counter);
	ENV_BUG_ON(val < 0);

	if (!val && env_atomic_cmpxchg(&rc->callback, 1, 0))
		rc->cb(rc->priv);
}

bool env_refcnt_inc(struct env_refcnt  *rc)
{
	int val;

	if (!env_atomic_read(&rc->freeze)) {
		val = env_atomic_inc_return(&rc->counter);
		if (!env_atomic_read(&rc->freeze))
			return !!val;
		else
			env_refcnt_dec(rc);
	}

	return 0;
}


void env_refcnt_freeze(struct env_refcnt *rc)
{
	env_atomic_inc(&rc->freeze);
}

void env_refcnt_register_zero_cb(struct env_refcnt *rc, env_refcnt_cb_t cb,
		void *priv)
{
	ENV_BUG_ON(!env_atomic_read(&rc->freeze));
	ENV_BUG_ON(env_atomic_read(&rc->callback));

	env_atomic_inc(&rc->counter);
	rc->cb = cb;
	rc->priv = priv;
	env_atomic_set(&rc->callback, 1);
	env_refcnt_dec(rc);
}

void env_refcnt_unfreeze(struct env_refcnt *rc)
{
	int val = env_atomic_dec_return(&rc->freeze);
	ENV_BUG_ON(val < 0);
}

bool env_refcnt_frozen(struct env_refcnt *rc)
{
	return !!env_atomic_read(&rc->freeze);
}

bool env_refcnt_zeroed(struct env_refcnt *rc)
{
	return (env_atomic_read(&rc->counter) == 0);
}
