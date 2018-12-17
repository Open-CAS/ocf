/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef ENGINE_DEBUG_H_
#define ENGINE_DEBUG_H_

#ifndef OCF_ENGINE_DEBUG
#define OCF_ENGINE_DEBUG 0
#endif

#ifndef OCF_DEBUG_TAG
#ifndef OCF_ENGINE_DEBUG_IO_NAME
#define OCF_ENGINE_DEBUG_IO_NAME "null"
#define OCF_DEBUG_TAG "engine"
#else
#define OCF_DEBUG_TAG "engine["OCF_ENGINE_DEBUG_IO_NAME"]"
#endif
#endif

#ifndef OCF_DEBUG
#define OCF_DEBUG OCF_ENGINE_DEBUG
#endif

#include "../ocf_debug.h"

#endif /* ENGINE_DEBUG_H_ */
