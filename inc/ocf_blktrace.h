/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _OCF_BLKTRACE_H_
#define _OCF_BLKTRACE_H_

#include "ocf/ocf_blktrace_declare.h"

#ifdef OCF_BLKTRACE

#include "ocf/ocf_types.h"
#include "../ocf_request.h"
#include "../ocf_core_priv.h"

#ifdef OCF_SIM
#define	OCF_BLKTRACE_SIGNATURE	98765432123456789
#define	OCF_BLKTRACE_SET_SIGNATURE(_blktrace)	(_blktrace)->signature = OCF_BLKTRACE_SIGNATURE
#define OCF_BLKTRACE_IS_VALID(_blktrace)	((_blktrace)->signature == OCF_BLKTRACE_SIGNATURE)
#else
#define	OCF_BLKTRACE_SET_SIGNATURE(_blktrace)
#define OCF_BLKTRACE_IS_VALID(_blktrace)	(1)
#endif	/* OCF_SIM */

typedef struct {
#ifdef OCF_SIM
	void *ocf_queue_metadata;	/* MUST be first */
	void *data;
	void *priv;
#endif
	ocf_volume_t volume;
	uint64_t addr;
	uint32_t bytes;
	uint8_t dir;
	uint8_t pa_id;
	ocf_blktrace_io_t *blktrace;
} ocf_io_t;

/* Lower case letters (used in ocf_sim blkparse) are originated by the OCF */
typedef enum {
	ocf_blktrace_action_new_app,		/* Q */
	ocf_blktrace_action_new_ocf,		/* q - A new I/O that was originated from the OCF */
	ocf_blktrace_action_remap,		/* A */
	ocf_blktrace_action_remap_to_cache,	/* a */
	ocf_blktrace_action_inserted,		/* I */
	ocf_blktrace_action_extracted,		/* e - Extracted from internal queue/lock */
	ocf_blktrace_action_async_lock,		/* l - Aquired an async lock */
	ocf_blktrace_action_async_wait,		/* w - Failed to aquire async lock - Waiter list */
	ocf_blktrace_action_async_resume,	/* r - Resume from an async lock */
	ocf_blktrace_action_sync_lock,		/* v - A sync lock */
	ocf_blktrace_action_sync_unlock,	/* u - A sync unlock */
	ocf_blktrace_action_issued,		/* D */
	ocf_blktrace_action_complete,		/* C */
	ocf_blktrace_action_debug,		/* z - Used for Debug */
	ocf_blktrace_action_cnt			/* The number of actions - Must be last */
} ocf_blktrace_action_t;

typedef struct {
	const char *file;
	const char *func;
	const char *text;
	const int line;
	const ocf_blktrace_action_t action;
} ocf_blktrace_const_data_t;

typedef struct {
	ocf_volume_t volume;
	uint64_t addr;
} ocf_blktrace_orig_on_remap_t;

typedef struct {
	void (*blktrace_ext_func)(const ocf_blktrace_const_data_t *const_data,
				 ocf_io_t *io,
				 ocf_blktrace_orig_on_remap_t *orig_on_remap,
				 ocf_blktrace_ts_t *ts);	/* [OT] - Current timestap */
	void (*volsim_create)(ocf_volume_t volume);
	void (*volsim_destroy)(ocf_volume_t volume);
} ocf_blktrace_register_t;

void ocf_blktrace_de_register(void);

void ocf_blktrace_new(const ocf_blktrace_const_data_t *const_data,
		      struct ocf_request *req, struct ocf_request *trigger_req);

void ocf_blktrace_register(const ocf_blktrace_register_t *reg);

void ocf_blktrace_remap_composite(const ocf_blktrace_const_data_t *const_data,
				ocf_volume_t volume, uint64_t addr, uint64_t caddr,
				ocf_forward_token_t token, uint8_t dir);

void ocf_blktrace_remap_to_be(const ocf_blktrace_const_data_t *const_data,
		      		     struct ocf_request *req);

void ocf_blktrace_remap_to_cache(const ocf_blktrace_const_data_t *const_data,
			struct ocf_request *req, uint64_t addr, uint8_t dir);

void ocf_blktrace_update(const ocf_blktrace_const_data_t *const_data, ocf_io_t *ocf_io);

void ocf_blktrace_update_req(const ocf_blktrace_const_data_t *const_data,
			struct ocf_request *req);

void ocf_blktrace_update_token(const ocf_blktrace_const_data_t *const_data,
				ocf_volume_t volume, uint64_t addr,
				ocf_forward_token_t token);

void ocf_blktrace_volsim_destroy(ocf_volume_t volume);

void ocf_blktrace_volsim_create(ocf_volume_t volume);

/* Can't use inline function because of cyclic include */
#define ocf_blktrace_get(_req)		(&(_req)->io.ocf_io_blktrace)

#define	OCF_BLKTRACE_CONST_DATA(_action, _txt)				\
		static const ocf_blktrace_const_data_t const_data = {	\
			.file = __FILE__,				\
			.func =  __func__,				\
			.text = _txt,					\
			.line = __LINE__,				\
			.action = _action				\
		}

#define	OCF_BLKTRACE_FUNC_CALL1(_blktrace_func, _action, _p1, _txt)	\
	do {								\
		OCF_BLKTRACE_CONST_DATA(_action, _txt);		\
		_blktrace_func(&const_data, _p1);			\
	} while (0)

#define	OCF_BLKTRACE_FUNC_CALL2(_blktrace_func, _action, _p1, _p2, _txt)	\
	do {									\
		OCF_BLKTRACE_CONST_DATA(_action, _txt);			\
		_blktrace_func(&const_data, _p1, _p2);				\
	} while (0)

#define	OCF_BLKTRACE_FUNC_CALL3(_blktrace_func, _action, _p1, _p2, _p3, _txt)	\
	do {									\
		OCF_BLKTRACE_CONST_DATA(_action, _txt);			\
		_blktrace_func(&const_data, _p1, _p2, _p3);			\
	} while (0)

#define	OCF_BLKTRACE_FUNC_CALL5(_blktrace_func, _action, _p1, _p2, _p3, _p4,	\
				_p5, _txt)					\
	do {									\
		OCF_BLKTRACE_CONST_DATA(_action, _txt);				\
		_blktrace_func(&const_data, _p1, _p2, _p3, _p4, _p5);		\
	} while (0)

#define	OCF_BLKTRACE_COMPLETE(_volume, _token, _addr, _error)		\
		OCF_BLKTRACE_FUNC_CALL3(ocf_blktrace_update_token,	\
					ocf_blktrace_action_complete,	\
					_volume, _token, _addr, _error)


#define	OCF_BLKTRACE_COMPLETE_IO(_io)					\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_update_req,	\
					ocf_blktrace_action_complete,	\
					ocf_io_to_req(_io), NULL)

#define	OCF_BLKTRACE_DEBUG_REQ(_req, _txt)				\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_update_req,	\
					ocf_blktrace_action_debug,	\
					_req, _txt)

#define	OCF_BLKTRACE_NEW_IO(_io)					\
		OCF_BLKTRACE_FUNC_CALL2(ocf_blktrace_new,		\
					ocf_blktrace_action_new_app,	\
					ocf_io_to_req(_io), NULL, NULL)

#define	OCF_BLKTRACE_NEW_OCF_REQ(_req, _trigger_req)			\
		OCF_BLKTRACE_FUNC_CALL2(ocf_blktrace_new,		\
				ocf_blktrace_action_new_ocf,		\
				_req, _trigger_req, NULL)

#define	OCF_BLKTRACE_REMAP_COMPOSITE(_volume, _addr, _caddr, _token, _dir) \
		OCF_BLKTRACE_FUNC_CALL5(ocf_blktrace_remap_composite,	\
				ocf_blktrace_action_remap_to_cache,	\
				_volume, _addr, _caddr, _token, _dir, NULL)

#define	OCF_BLKTRACE_REMAP_TO_BE(_req)					\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_remap_to_be,	\
				ocf_blktrace_action_remap, _req, NULL)

#define	OCF_BLKTRACE_REMAP_TO_CACHE(_req, _addr, _dir)			\
	do {									\
		if (OCF_BLKTRACE_IS_VALID(&(_req)->io.ocf_io_blktrace))	\
			OCF_BLKTRACE_FUNC_CALL3(ocf_blktrace_remap_to_cache,	\
					ocf_blktrace_action_remap_to_cache,	\
					_req, _addr, _dir, NULL);		\
		else OCF_BLKTRACE_NEW_OCF_REQ(_req, NULL);			\
	} while (0)

#define	OCF_BLKTRACE_REQ_ASYNC_LOCK(_req)				\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_update_req,	\
				ocf_blktrace_action_async_lock,		\
				_req, NULL)

#define	OCF_BLKTRACE_REQ_ASYNC_RESUME(_req)				\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_update_req,	\
				ocf_blktrace_action_async_resume,	\
				_req, NULL)

#define	OCF_BLKTRACE_REQ_ASYNC_WAIT(_req)				\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_update_req,	\
				ocf_blktrace_action_async_wait,		\
				_req, NULL)

#define	OCF_BLKTRACE_REQ_Q_POP(_req)					\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_update_req,	\
				ocf_blktrace_action_extracted,		\
				_req, NULL)

#define	OCF_BLKTRACE_REQ_Q_PUSH(_req)					\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_update_req,	\
				ocf_blktrace_action_inserted,		\
				_req, NULL)

#define	OCF_BLKTRACE_REQ_SYNC_LOCK(_req)				\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_update_req,	\
				ocf_blktrace_action_sync_lock,		\
				_req, NULL)

#define	OCF_BLKTRACE_REQ_SYNC_UNLOCK(_req)				\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_update_req,	\
				ocf_blktrace_action_sync_unlock,	\
				_req, NULL)

#define	OCF_BLKTRACE_SUBMIT_IO(_ocf_io)					\
		OCF_BLKTRACE_FUNC_CALL1(ocf_blktrace_update,		\
					ocf_blktrace_action_issued,	\
					_ocf_io, NULL)

#define	OCF_BLKTRACE_CLEAR(_blktrace)	env_memset((_blktrace), sizeof(*(_blktrace)), 0)
#define	OCF_BLKTRACE_COPY(_to, _from)	(*(_to) = *(_from))

#ifdef OCF_SIM
#define OCF_BLKTRACE_VOLSIM_INIT(_volume)		\
	do {						\
		ocf_blktrace_volsim_create(_volume);	\
		if (!(_volume)->ocf_volsim) {		\
			return -OCF_ERR_NO_MEM;		\
		}					\
	} while (0)

#define OCF_BLKTRACE_VOLSIM_DEINIT(_volume)	ocf_blktrace_volsim_destroy(_volume)

#define OCF_BLKTRACE_VOLSIM_MOVE(_to, _from)			\
	do {							\
		void *temp = (_to)->ocf_volsim;			\
		(_to)->ocf_volsim = (_from)->ocf_volsim;	\
		(_from)->ocf_volsim = temp;			\
	} while (0)
#else
#define OCF_BLKTRACE_VOLSIM_INIT(_volume)
#define OCF_BLKTRACE_VOLSIM_DEINIT(_volume)
#define OCF_BLKTRACE_VOLSIM_MOVE(_to, _from)
#endif

#else

#define	OCF_BLKTRACE_SET_SIGNATURE(_blktrace)
#define OCF_BLKTRACE_IS_VALID(_blktrace)		(1)

#define	OCF_BLKTRACE_COMPLETE(_volume, _token, _addr, _error)
#define	OCF_BLKTRACE_COMPLETE_IO(_io)
#define	OCF_BLKTRACE_DEBUG_REQ(_req, _txt)
#define	OCF_BLKTRACE_NEW_IO(_io)
#define	OCF_BLKTRACE_NEW_OCF_FWD_IO(_io, _trigger_io)
#define	OCF_BLKTRACE_NEW_OCF_REQ(_req, _trigger_req)
#define	OCF_BLKTRACE_REMAP_COMPOSITE(_volume, _addr, _caddr, _token, _dir)
#define	OCF_BLKTRACE_REMAP_TO_BE(_req)
#define	OCF_BLKTRACE_REMAP_TO_CACHE(_req, _addr, _dir)
#define	OCF_BLKTRACE_REQ_ASYNC_LOCK(_req)
#define	OCF_BLKTRACE_REQ_ASYNC_RESUME(_req)
#define	OCF_BLKTRACE_REQ_ASYNC_WAIT(_req)
#define	OCF_BLKTRACE_REQ_Q_POP(_req)
#define	OCF_BLKTRACE_REQ_Q_PUSH(_req)
#define	OCF_BLKTRACE_REQ_SYNC_LOCK(_req)
#define	OCF_BLKTRACE_REQ_SYNC_UNLOCK(_req)
#define	OCF_BLKTRACE_SUBMIT_IO(_ocf_io)
#define	OCF_BLKTRACE_CLEAR(_blktrace)
#define	OCF_BLKTRACE_COPY(_to, _from)
#define OCF_BLKTRACE_VOLSIM_INIT(_volume)
#define OCF_BLKTRACE_VOLSIM_DEINIT(_volume)
#define OCF_BLKTRACE_VOLSIM_MOVE(_to, _from)

#endif	/* OCF_BLKTRACE */

#endif	/* _OCF_BLKTRACE_H_ */
