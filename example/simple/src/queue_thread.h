/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

int initialize_threads(struct ocf_queue *mngt_queue, struct ocf_queue *io_queue);
void queue_thread_kick(ocf_queue_t q);
void queue_thread_stop(ocf_queue_t q);
