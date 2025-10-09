/*
 * Copyright(c) 2019-2022 Intel Corporation
 * Copyright(c) 2024-2025 Huawei Technologies
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __UTILS_PIPELINE_H__
#define __UTILS_PIPELINE_H__

#include "ocf/ocf.h"

enum ocf_pipeline_step_type {
	ocf_pipeline_step_single,
	ocf_pipeline_step_foreach,
	ocf_pipeline_step_conditional,
	ocf_pipeline_step_terminator,
};

enum ocf_pipeline_arg_type {
	ocf_pipeline_arg_none,
	ocf_pipeline_arg_int,
	ocf_pipeline_arg_ptr,
	ocf_pipeline_arg_terminator,
};

struct ocf_pipeline_arg {
	enum ocf_pipeline_arg_type type;
	union {
		int i;
		void *p;
	} val;
};

typedef struct ocf_pipeline_arg *ocf_pipeline_arg_t;

#define OCF_PL_ARG_NONE() \
	{ .type = ocf_pipeline_arg_none, }

#define OCF_PL_ARG_INT(_int) \
	{ .type = ocf_pipeline_arg_int, .val.i = _int }

#define OCF_PL_ARG_PTR(_ptr) \
	{ .type = ocf_pipeline_arg_ptr, .val.p = _ptr }

#define OCF_PL_ARG_TERMINATOR() \
	{ .type = ocf_pipeline_arg_terminator, }

static inline int ocf_pipeline_arg_get_int(ocf_pipeline_arg_t arg)
{
	ENV_BUG_ON(arg->type != ocf_pipeline_arg_int);

	return arg->val.i;
}

static inline void *ocf_pipeline_arg_get_ptr(ocf_pipeline_arg_t arg)
{
	ENV_BUG_ON(arg->type != ocf_pipeline_arg_ptr);

	return arg->val.p;
}

typedef struct ocf_pipeline *ocf_pipeline_t;

typedef void (*ocf_pipeline_step_hndl_t)(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg);

typedef void (*ocf_pipeline_finish_t)(ocf_pipeline_t pipeline,
		void *priv, int error);

typedef bool (*ocf_pipeline_cond_step_predicate_t)(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg);

struct ocf_pipeline_step {
	char *name;
	enum ocf_pipeline_step_type type;
	ocf_pipeline_step_hndl_t hndl;
	ocf_pipeline_cond_step_predicate_t pred;
	union {
		struct ocf_pipeline_arg arg;
		struct ocf_pipeline_arg *args;
	};
};

typedef struct ocf_pipeline_step *ocf_pipeline_step_t;

#define xstr(a) str(a)
#define str(a) #a

#define OCF_PL_STEP(_hndl) \
	{ \
		.name = xstr(_hndl), \
		.type = ocf_pipeline_step_single, \
		.hndl = _hndl, \
	}

#define OCF_PL_STEP_ARG_INT(_hndl, _int) \
	{ \
		.name = xstr(_hndl), \
		.type = ocf_pipeline_step_single, \
		.hndl = _hndl, \
		.arg = { \
			.type = ocf_pipeline_arg_int, \
			.val.i = _int, \
		} \
	}

#define OCF_PL_STEP_ARG_PTR(_hndl, _ptr) \
	{ \
		.name = xstr(_hndl), \
		.type = ocf_pipeline_step_single, \
		.hndl = _hndl, \
		.arg = { \
			.type = ocf_pipeline_arg_ptr, \
			.val.p = _ptr, \
		} \
	}

#define OCF_PL_STEP_FOREACH(_hndl, _args) \
	{ \
		.name = xstr(_hndl), \
		.type = ocf_pipeline_step_foreach, \
		.hndl = _hndl, \
		.args = _args, \
	}

#define OCF_PL_STEP_TERMINATOR() \
	{ \
		.name = "<TERMINATOR>", \
		.type = ocf_pipeline_step_terminator, \
	}

#define OCF_PL_STEP_COND(_pred, _hndl) \
	{ \
		.name = xstr(_hndl), \
		.pred = _pred, \
		.type = ocf_pipeline_step_conditional, \
		.hndl = _hndl, \
	}	

#define OCF_PL_STEP_COND_ARG_INT(_pred, _hndl, _int) \
	{ \
		.name = xstr(_hndl), \
		.pred = _pred, \
		.type = ocf_pipeline_step_conditional, \
		.hndl = _hndl, \
		.arg = { \
			.type = ocf_pipeline_arg_int, \
			.val.i = _int, \
		} \
	}

#define OCF_PL_STEP_COND_ARG_PTR(_pred, _hndl, _ptr) \
	{ \
		.name = xstr(_hndl), \
		.pred = _pred, \
		.type = ocf_pipeline_step_conditional, \
		.hndl = _hndl, \
		.arg = { \
			.type = ocf_pipeline_arg_ptr, \
			.val.p = _ptr, \
		} \
	}

struct ocf_pipeline_properties {
	uint32_t priv_size;
	ocf_pipeline_finish_t finish;
	struct ocf_pipeline_step steps[];
};

int ocf_pipeline_create(ocf_pipeline_t *pipeline, ocf_cache_t cache,
		struct ocf_pipeline_properties *properties);

void ocf_pipeline_set_priv(ocf_pipeline_t pipeline, void *priv);

void *ocf_pipeline_get_priv(ocf_pipeline_t pipeline);

void ocf_pipeline_destroy(ocf_pipeline_t pipeline);

void ocf_pipeline_next(ocf_pipeline_t pipeline);

void ocf_pipeline_finish(ocf_pipeline_t pipeline, int error);

#define OCF_PL_NEXT_RET(pipeline) ({ \
	ocf_pipeline_next(pipeline); \
	return; \
})

#define OCF_PL_FINISH_RET(pipeline, error) ({ \
	ocf_pipeline_finish(pipeline, error); \
	return; \
})

#define OCF_PL_NEXT_ON_SUCCESS_RET(pipeline, error) ({ \
	if (error) \
		ocf_pipeline_finish(pipeline, error); \
	else \
		ocf_pipeline_next(pipeline); \
	return; \
})


#endif /* __UTILS_PIPELINE_H__ */
