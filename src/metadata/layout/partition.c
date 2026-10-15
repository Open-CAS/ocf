/*
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "partition.h"

void ocf_user_part_config_validate(
		const struct ocf_user_part_config *part_config,
		struct ocf_user_part_config_validity *valid)
{
	env_memset(valid, sizeof(*valid), 0);

	valid->name =
		part_config->name[0] != '\0' &&
		env_strnlen(part_config->name, sizeof(part_config->name)) <
		OCF_IO_CLASS_NAME_MAX;

	valid->min_size =
		part_config->min_size <= part_config->max_size;

	valid->max_size =
		part_config->max_size <= PARTITION_SIZE_MAX;

	valid->priority =
		part_config->priority == OCF_IO_CLASS_PRIO_PINNED ||
		(part_config->priority >= OCF_IO_CLASS_PRIO_HIGHEST &&
		 part_config->priority <= OCF_IO_CLASS_PRIO_LOWEST);

	valid->cache_mode =
		part_config->cache_mode >= ocf_cache_mode_none &&
		part_config->cache_mode <= ocf_cache_mode_max;
}

void ocf_user_parts_validate(
		const struct ocf_superblock_config *superblock,
		const struct ocf_user_part_config *part_config,
		struct ocf_user_parts_validity *valid)
{
	uint32_t valid_parts_no = 0;
	uint64_t min_size = 0;
	ocf_part_id_t part_id;

	env_memset(valid, sizeof(*valid), 0);

	for (part_id = 0; part_id < OCF_USER_IO_CLASS_MAX; part_id++) {
		if (!part_config[part_id].flags.valid)
			continue;

		valid_parts_no++;
		min_size += part_config[part_id].min_size;
	}

	valid->valid_parts_no =
		superblock->valid_parts_no == valid_parts_no;

	valid->min_size =
		min_size <= PARTITION_SIZE_MAX;
}
