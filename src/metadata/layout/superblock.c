/*
 * Copyright(c) 2012-2022 Intel Corporation
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "superblock.h"
#include "layout.h"

static bool ocf_superblock_config_line_size_is_valid(uint64_t size)
{
	switch (size) {
	case ocf_cache_line_size_4:
	case ocf_cache_line_size_8:
	case ocf_cache_line_size_16:
	case ocf_cache_line_size_32:
	case ocf_cache_line_size_64:
		return true;
	default:
		return false;
	}
}

void ocf_superblock_config_validate(
		const struct ocf_superblock_config *superblock,
		struct ocf_superblock_config_validity *valid)
{
	env_memset(valid, sizeof(*valid), 0);

	valid->magic_number =
		superblock->magic_number == CACHE_MAGIC_NUMBER;
	if (!valid->magic_number)
		return;

	valid->metadata_version =
		superblock->metadata_version == METADATA_VERSION();
	if (!valid->metadata_version)
		return;

	valid->checksum =
		superblock->checksum[metadata_segment_sb_config] ==
		ocf_metadata_segment_layout_checksum_superblock(superblock);

	valid->adapter_name =
		!env_strncmp(superblock->adapter_name, OCF_ADAPTER_NAME_SIZE,
				ENV_ADAPTER_NAME, OCF_ADAPTER_NAME_SIZE);

	valid->adapter_version =
		superblock->adapter_version == ADAPTER_VERSION();

	valid->metadata_4k_mode =
		superblock->metadata_4k_mode == METADATA_4K_MODE();

	valid->clean_shutdown =
		superblock->clean_shutdown <= ocf_metadata_clean_shutdown;

	valid->dirty_flushed =
		superblock->dirty_flushed <= DIRTY_FLUSHED;

	valid->flapping_idx =
		superblock->flapping_idx <= 1;

	valid->cache_mode =
		superblock->cache_mode >= 0 &&
		superblock->cache_mode < ocf_cache_mode_max;

	valid->name =
		env_strnlen(superblock->name, sizeof(superblock->name)) <
		OCF_CACHE_NAME_SIZE;

	valid->valid_parts_no =
		superblock->valid_parts_no <= OCF_USER_IO_CLASS_MAX;

	valid->line_size =
		ocf_superblock_config_line_size_is_valid(superblock->line_size);

	valid->core_count =
		superblock->core_count <= OCF_CORE_NUM;

	valid->cleaning_policy_type =
		superblock->cleaning_policy_type >= 0 &&
		superblock->cleaning_policy_type < ocf_cleaning_max;

	valid->cleaner_disabled =
		!superblock->cleaner_disabled ||
		superblock->cleaning_policy_type == ocf_cleaning_nop;

	valid->promotion_policy_type =
		superblock->promotion_policy_type >= 0 &&
		superblock->promotion_policy_type < ocf_promotion_max;
}
