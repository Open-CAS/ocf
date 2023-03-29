/*
 * Copyright(c) 2019-2022 Intel Corporation
 * Copyright(c) 2023 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ocf/ocf.h"
#include "../engine/cache_engine.h"
#include "../engine/engine_common.h"
#include "../ocf_request.h"
#include "utils_pipeline.h"

#define OCF_PIPELINE_ALIGNMENT 64

struct ocf_pipeline {
	struct ocf_pipeline_properties *properties;
	struct ocf_request *req;
	int next_step;
	int next_arg;
	bool finish;
	int error;

	void *priv;
};

static int _ocf_pipeline_run_step(struct ocf_request *req)
{
	ocf_pipeline_t pipeline = req->priv;
	struct ocf_pipeline_step *step;
	ocf_pipeline_arg_t arg;

	if (pipeline->finish) {
		pipeline->properties->finish(pipeline, pipeline->priv,
				pipeline->error);
		return 0;
	}

	while (true) {
		step = &pipeline->properties->steps[pipeline->next_step];
		switch (step->type) {
		case ocf_pipeline_step_single:
			pipeline->next_step++;
			step->hndl(pipeline, pipeline->priv, &step->arg);
			return 0;
		case ocf_pipeline_step_conditional:
			pipeline->next_step++;
			if (step->pred(pipeline, pipeline->priv, &step->arg)) {
				step->hndl(pipeline, pipeline->priv, &step->arg);
				return 0;
			}	
			continue;
		case ocf_pipeline_step_foreach:
			arg = &step->args[pipeline->next_arg++];
			if (arg->type == ocf_pipeline_arg_terminator) {
				pipeline->next_arg = 0;
				pipeline->next_step++;
				continue;
			}
			step->hndl(pipeline, pipeline->priv, arg);
			return 0;
		case ocf_pipeline_step_terminator:
			pipeline->properties->finish(pipeline, pipeline->priv,
					pipeline->error);
			return 0;
		default:
			ENV_BUG();
		}
	}

	return 0;
}

static const struct ocf_io_if _io_if_pipeline = {
	.read = _ocf_pipeline_run_step,
	.write = _ocf_pipeline_run_step,
};

int ocf_pipeline_create(ocf_pipeline_t *pipeline, ocf_cache_t cache,
		struct ocf_pipeline_properties *properties)
{
	ocf_pipeline_t tmp_pipeline;
	struct ocf_request *req;

	tmp_pipeline = env_vzalloc(sizeof(*tmp_pipeline) +
			properties->priv_size + OCF_PIPELINE_ALIGNMENT);
	if (!tmp_pipeline)
		return -OCF_ERR_NO_MEM;

	if (properties->priv_size > 0) {
		uintptr_t priv = (uintptr_t)tmp_pipeline + sizeof(*tmp_pipeline);
		priv = OCF_DIV_ROUND_UP(priv, OCF_PIPELINE_ALIGNMENT) * OCF_PIPELINE_ALIGNMENT;
		tmp_pipeline->priv = (void *)priv;
	}

	req = ocf_req_new(cache->mngt_queue, NULL, 0, 0, 0);
	if (!req) {
		env_vfree(tmp_pipeline);
		return -OCF_ERR_NO_MEM;
	}

	tmp_pipeline->properties = properties;
	tmp_pipeline->req = req;
	tmp_pipeline->next_step = 0;
	tmp_pipeline->finish = false;
	tmp_pipeline->error = 0;

	req->info.internal = true;
	req->io_if = &_io_if_pipeline;
	req->priv = tmp_pipeline;

	*pipeline = tmp_pipeline;

	return 0;
}

void ocf_pipeline_destroy(ocf_pipeline_t pipeline)
{
	ocf_req_put(pipeline->req);
	env_vfree(pipeline);
}

void ocf_pipeline_set_priv(ocf_pipeline_t pipeline, void *priv)
{
	pipeline->priv = priv;
}

void *ocf_pipeline_get_priv(ocf_pipeline_t pipeline)
{
	return pipeline->priv;
}

void ocf_pipeline_next(ocf_pipeline_t pipeline)
{
	ocf_engine_push_req_front(pipeline->req, false);
}

void ocf_pipeline_finish(ocf_pipeline_t pipeline, int error)
{
	pipeline->finish = true;
	pipeline->error = error;
	ocf_engine_push_req_front(pipeline->req, false);
}
