/*
 * Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * OCF Classifier infrastructure
 */

#ifndef __OCF_CLASSIFIER_COMMON_H__
#define __OCF_CLASSIFIER_COMMON_H__

#define OCF_CLASSIFIER_IGNORE_OCF	(1 << 0)	/* skip OCF seq_cutoff admission policy [sequential=pt] */
#define OCF_CLASSIFIER_SWAP		(1 << 1)	/* use OCF swap admission policy [swap=wb] */
#define OCF_CLASSIFIER_WRITE_CHUNKS	(1 << 2)	/* locality-based write blocks identification */

#endif /* __OCF_CLASSIFIER_COMMON_H__ */
