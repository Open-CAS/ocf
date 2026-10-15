/*
 * Copyright(c) 2026 Unvertical
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "core.h"

void ocf_core_meta_config_validate(
		const struct ocf_superblock_config *superblock,
		ocf_core_id_t core_id,
		const struct ocf_core_meta_config *core_config,
		struct ocf_core_meta_config_validity *valid)
{
	uint32_t seq_cutoff_threshold, seq_detect_promotion_count;
	uint32_t seq_detect_promotion_threshold;
	int seq_cutoff_policy;

	if (!env_bit_test(core_id, superblock->valid_core_bitmap)) {
		/* Core is not in use - there is nothing to check */
		env_memset(valid, sizeof(*valid), true);
		return;
	}

	env_memset(valid, sizeof(*valid), 0);

	valid->name =
		core_config->name[0] != '\0' &&
		env_strnlen(core_config->name, sizeof(core_config->name)) <
		OCF_CORE_NAME_SIZE;

	valid->seq_no =
		core_config->seq_no <= superblock->curr_core_seq_no;

	seq_cutoff_threshold =
		env_atomic_read(&core_config->seq_cutoff_threshold);
	valid->seq_cutoff_threshold =
		seq_cutoff_threshold >= OCF_SEQ_CUTOFF_MIN_THRESHOLD &&
		seq_cutoff_threshold <= OCF_SEQ_CUTOFF_MAX_THRESHOLD;

	seq_cutoff_policy =
		env_atomic_read(&core_config->seq_cutoff_policy);
	valid->seq_cutoff_policy =
		seq_cutoff_policy >= 0 &&
		seq_cutoff_policy < ocf_seq_cutoff_policy_max;

	seq_detect_promotion_count =
		env_atomic_read(&core_config->seq_detect_promotion_count);
	valid->seq_detect_promotion_count =
		seq_detect_promotion_count >=
				OCF_SEQ_DETECT_MIN_PROMOTION_COUNT &&
		seq_detect_promotion_count <=
				OCF_SEQ_DETECT_MAX_PROMOTION_COUNT;

	seq_detect_promotion_threshold =
		env_atomic_read(&core_config->seq_detect_promotion_threshold);
	valid->seq_detect_promotion_threshold =
		seq_detect_promotion_threshold <=
				OCF_SEQ_DETECT_MAX_PROMOTION_THRESHOLD;
}

void ocf_cores_validate(const struct ocf_superblock_config *superblock,
		const struct ocf_core_meta_config *core_config,
		struct ocf_cores_validity *valid)
{
	ocf_core_id_t i, j;

	env_memset(valid, sizeof(*valid), 0);

	/*
	 * Sequence number is assigned only on atomic cache device, otherwise
	 * it is OCF_SEQ_NO_INVALID for all cores.
	 */
	for (i = 0; i < OCF_CORE_NUM; i++) {
		if (!env_bit_test(i, superblock->valid_core_bitmap))
			continue;

		if (core_config[i].seq_no == OCF_SEQ_NO_INVALID)
			continue;

		for (j = i + 1; j < OCF_CORE_NUM; j++) {
			if (!env_bit_test(j, superblock->valid_core_bitmap))
				continue;

			if (core_config[i].seq_no == core_config[j].seq_no)
				return;
		}
	}

	valid->seq_no = true;
}

void ocf_metadata_uuid_validate(
		const struct ocf_superblock_config *superblock,
		ocf_core_id_t core_id,
		const struct ocf_metadata_uuid *uuid,
		struct ocf_metadata_uuid_validity *valid)
{
	if (!env_bit_test(core_id, superblock->valid_core_bitmap)) {
		/* Core is not in use - there is nothing to check */
		env_memset(valid, sizeof(*valid), true);
		return;
	}

	env_memset(valid, sizeof(*valid), 0);

	valid->size = uuid->size <= OCF_VOLUME_UUID_MAX_SIZE;
}
