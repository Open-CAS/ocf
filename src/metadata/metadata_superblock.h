/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2024 Huawei Technologies
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __METADATA_SUPERBLOCK_H__
#define __METADATA_SUPERBLOCK_H__

#include "ocf/ocf.h"
#include "metadata_common.h"
#include "layout/superblock.h"

struct ocf_metadata_ctrl;
struct ocf_metadata_segment;
struct ocf_metadata_raw;

void ocf_metadata_set_shutdown_status(ocf_cache_t cache,
		enum ocf_metadata_shutdown_status shutdown_status,
		ocf_metadata_end_t cmpl, void *priv);

void ocf_metadata_load_superblock(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv);

void ocf_metadata_flush_superblock(ocf_cache_t cache,
		ocf_metadata_end_t cmpl, void *priv);

int ocf_metadata_superblock_init(
		struct ocf_metadata_segment **self,
		struct ocf_cache *cache,
		struct ocf_metadata_raw *raw);

void ocf_metadata_superblock_destroy(
		struct ocf_cache *cache,
		struct ocf_metadata_segment *self);

uint32_t ocf_metadata_superblock_get_checksum(
		struct ocf_metadata_segment *self,
		enum ocf_metadata_segment_id segment);

void ocf_metadata_superblock_set_checksum(
		struct ocf_metadata_segment *self,
		enum ocf_metadata_segment_id segment,
		uint32_t csum);

bool ocf_metadata_superblock_get_clean_shutdown(
		struct ocf_metadata_segment *self);

unsigned ocf_metadata_superblock_get_flapping_idx(
		struct ocf_metadata_segment *self);

unsigned ocf_metadata_superblock_get_next_flapping_idx(
		struct ocf_metadata_segment *self);

int ocf_metadata_validate_superblock(ocf_ctx_t ctx,
		struct ocf_superblock_config *superblock);

struct ocf_metadata_read_sb_ctx;

typedef void (*ocf_metadata_read_sb_end_t)(
                struct ocf_metadata_read_sb_ctx *context);

struct ocf_metadata_read_sb_ctx {
        struct ocf_superblock_config superblock;
        ocf_metadata_read_sb_end_t cmpl;
        ocf_ctx_t ctx;
        void *priv1;
        void *priv2;
        int error;
};

int ocf_metadata_read_sb(ocf_ctx_t ctx, ocf_volume_t volume,
		ocf_metadata_read_sb_end_t cmpl, void *priv1, void *priv2);

void ocf_metadata_sb_zero(struct ocf_metadata_segment *self,
		ocf_metadata_end_t cmpl, void *priv);

#endif /* __METADATA_SUPERBLOCK_H__ */
