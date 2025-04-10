/*
 * Copyright(c) 2021-2021 Intel Corporation
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef QUEUE_THREAD_H

int initialize_threads(struct ocf_queue* mngt_queue, struct ocf_queue* io_queue[], int mcpus);
void queue_thread_kick(ocf_queue_t q);
void queue_thread_stop(ocf_queue_t q);

#endif // QUEUE_THREAD_H
