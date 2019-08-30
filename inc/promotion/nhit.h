/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_PROMOTION_NHIT_H__
#define __OCF_PROMOTION_NHIT_H__

enum nhit_param {
	nhit_insertion_threshold,
	nhit_trigger_threshold,
	nhit_param_max
};

#define NHIT_MIN_THRESHOLD 2
#define NHIT_MAX_THRESHOLD 1000
#define NHIT_THRESHOLD_DEFAULT 3

#define NHIT_MIN_TRIGGER 0
#define NHIT_MAX_TRIGGER 100
#define NHIT_TRIGGER_DEFAULT 80

#endif /* __OCF_PROMOTION_NHIT_H__ */
