/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OCF_CLASSIFIER_H__
#define __OCF_CLASSIFIER_H__

#include "../ocf_core_priv.h"
#include "ocf/ocf_classifier_common.h"

#define OCF_CLASSIFIER_HANDLERS_X \
	X(write_chunks)

/* OCF_CLASSIFIER arguments:
 *  name - classifier name
 *  type - data element to allocate
 *  cnt - number of data types
 *
 *  OHASH_SIZE must be defined before to call OCF_CLASSIFIER.  If data element is not using
 *  ohash, then OHASH_SIZE must be set to 0.
 */
#define OCF_CLASSIFIER(name, type, cnt)									\
	void ocf_classifier_create_ ## name(ocf_core_t core) {						\
		core->classifier_handler_ ## name = env_zalloc((cnt) * sizeof(type), 0);		\
		if (OHASH_SIZE) ocf_ohash_create(core, core->classifier_handler_ ## name, OHASH_SIZE,	\
						 "classifier_handler_" # name ); }			\
	void ocf_classifier_destroy_ ## name(ocf_core_t core) {						\
		if (OHASH_SIZE) ocf_ohash_destroy(core->classifier_handler_ ## name);			\
		env_free(core->classifier_handler_ ## name); }						\
	static void *get_classifier_handler(ocf_core_t core) {						\
		return (core)->classifier_handler_ ## name; }						\
	bool ocf_classifier_ ## name(struct ocf_request *req)

#define X(classifier)							\
	void ocf_classifier_create_##classifier(ocf_core_t core);	\
	void ocf_classifier_destroy_##classifier(ocf_core_t core);	\
	bool ocf_classifier_##classifier(struct ocf_request *req);
OCF_CLASSIFIER_HANDLERS_X
#undef X

void ocf_classifier(struct ocf_request *);

#endif /* __OCF_CLASSIFIER_H__ */
