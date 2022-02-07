/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../engine/cache_engine.h"
#include "../engine/engine_common.h"
#include "../ocf_request.h"
#include "utils_parallelize.h"

struct ocf_parallelize {
	ocf_cache_t cache;
	ocf_parallelize_handle_t handle;
	ocf_parallelize_finish_t finish;
	void *priv;

	unsigned shards_cnt;
	env_atomic remaining;
	env_atomic error;

	struct ocf_request *reqs[];
};

static int _ocf_parallelize_hndl(struct ocf_request *req)
{
	ocf_parallelize_t parallelize = req->priv;
	ocf_parallelize_finish_t finish;
	void *priv;
	int error;

	error = parallelize->handle(parallelize, parallelize->priv,
			req->byte_position, parallelize->shards_cnt);

	env_atomic_cmpxchg(&parallelize->error, 0, error);

	if (env_atomic_dec_return(&parallelize->remaining))
		return 0;

	finish = parallelize->finish;
	priv = parallelize->priv;
	error = env_atomic_read(&parallelize->error);

	finish(parallelize, priv, error);

	return 0;
}

static const struct ocf_io_if _io_if_parallelize = {
	.read = _ocf_parallelize_hndl,
	.write = _ocf_parallelize_hndl,
};

int ocf_parallelize_create(ocf_parallelize_t *parallelize,
		ocf_cache_t cache, unsigned shards_cnt, uint32_t priv_size,
		ocf_parallelize_handle_t handle,
		ocf_parallelize_finish_t finish)
{
	ocf_parallelize_t tmp_parallelize;
	ocf_queue_t queue;
	size_t prl_size;
	unsigned queue_count = 0;
	int result, i;

	list_for_each_entry(queue, &cache->io_queues, list)
		queue_count++;

	if (shards_cnt == 0)
		shards_cnt = queue_count;

	prl_size = sizeof(*tmp_parallelize) +
			shards_cnt * sizeof(*tmp_parallelize->reqs);

	tmp_parallelize = env_vzalloc(prl_size + priv_size);
	if (!tmp_parallelize)
		return -OCF_ERR_NO_MEM;

	if (priv_size > 0)
		tmp_parallelize->priv = (void *)tmp_parallelize + prl_size;

	tmp_parallelize->cache = cache;
	tmp_parallelize->handle = handle;
	tmp_parallelize->finish = finish;

	tmp_parallelize->shards_cnt = shards_cnt;
	env_atomic_set(&tmp_parallelize->remaining, shards_cnt);
	env_atomic_set(&tmp_parallelize->error, 0);

	for (i = 0; i < shards_cnt;) {
		list_for_each_entry(queue, &cache->io_queues, list) {
			if (i == shards_cnt)
				break;
			tmp_parallelize->reqs[i] = ocf_req_new(queue,
					NULL, 0, 0, 0);
			if (!tmp_parallelize->reqs[i]) {
				result = -OCF_ERR_NO_MEM;
				goto err_reqs;
			}
			tmp_parallelize->reqs[i]->info.internal = true;
			tmp_parallelize->reqs[i]->io_if = &_io_if_parallelize;
			tmp_parallelize->reqs[i]->byte_position = i;
			tmp_parallelize->reqs[i]->priv = tmp_parallelize;
			i++;
		}
	}

	*parallelize = tmp_parallelize;

	return 0;

err_reqs:
	while (i--)
		ocf_req_put(tmp_parallelize->reqs[i]);
	env_vfree(tmp_parallelize);

	return result;
}

void ocf_parallelize_destroy(ocf_parallelize_t parallelize)
{
	int i;

	for (i = 0; i < parallelize->shards_cnt; i++)
		ocf_req_put(parallelize->reqs[i]);

	env_vfree(parallelize);
}

void *ocf_parallelize_get_priv(ocf_parallelize_t parallelize)
{
	return parallelize->priv;
}

void ocf_parallelize_set_priv(ocf_parallelize_t parallelize, void *priv)
{
	parallelize->priv = priv;
}

void ocf_parallelize_run(ocf_parallelize_t parallelize)
{
	int i;

	for (i = 0; i < parallelize->shards_cnt; i++)
		ocf_engine_push_req_front(parallelize->reqs[i], false);
}
