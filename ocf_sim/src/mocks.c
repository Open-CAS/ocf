/*
 * Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mocks.h"
#undef ARRAY_SIZE
#include "cas_lib.h"

static int _cache_mngt_read_lock_sync(ocf_cache_t cache)
{
	return 0;
}

static int _cache_mngt_lock_sync(ocf_cache_t cache)
{
	return 0;
}

struct cache_mngt_list_ctx {
	struct kcas_cache_list *list;
	int pos;
};

static int cache_mngt_list_caches_visitor(ocf_cache_t cache, void *cntx)
{
	struct cache_mngt_list_ctx *context = cntx;
	struct kcas_cache_list *list = context->list;
	uint16_t id;

	ENV_BUG_ON(cache_id_from_name(&id, ocf_cache_get_name(cache)));

	if (context->pos++ < list->id_position)
		return 0;

	if (list->in_out_num >= ARRAY_SIZE(list->cache_id_tab))
		return 1;

	list->cache_id_tab[list->in_out_num] = id;
	list->in_out_num++;

	return 0;
}

int cache_mngt_list_caches(struct kcas_cache_list* list)
{
	struct cache_mngt_list_ctx context = {
		.list = list,
		.pos = 0
	};

	list->in_out_num = 0;
	return ocf_mngt_cache_visit(ctx, cache_mngt_list_caches_visitor,
			&context);
}

// this mock for ocf_sim purpuse, to avoid checking the "cache1,cache2,...." are
// real blk device
char* realpath(const char* __restrict __name, char* __restrict __resolved)
{
	char* path;
	if (__resolved)
		path = __resolved;
	else
		path = malloc(strlen(__name) + 1);

	ENV_BUG_ON(!path);
	strcpy(path, __name);

	return path;
}

int cache_mngt_get_info(struct kcas_cache_info* info)
{
	uint32_t i, j;
	int result;
	ocf_cache_t cache;
	ocf_core_t core;
	const struct ocf_volume_uuid* uuid;

	result = mngt_get_cache_by_id(ctx, info->cache_id, &cache);
	if (result)
		return result;

	result = _cache_mngt_read_lock_sync(cache);
	if (result)
		goto put;

	result = ocf_cache_get_info(cache, &info->info);
	if (result)
		goto put;

	if (info->info.attached && !info->info.standby_detached) {
		uuid = ocf_cache_get_uuid(cache);
		// BUG_ON(!uuid);
		strncpy(info->cache_path_name, uuid->data,
			min(sizeof(info->cache_path_name), uuid->size));
	}
	else {
		memset(info->cache_path_name, 0, sizeof(info->cache_path_name));
	}
	/* Collect cores IDs */
	for (i = 0, j = 0; j < info->info.core_count &&
		i < OCF_CORE_MAX; i++) {
		if (get_core_by_id(cache, i, &core))
			continue;

		info->core_id[j] = i;
		j++;
	}

put:
	ocf_mngt_cache_put(cache);
	return result;
}

#ifdef OCF_DEBUG_STATS
static int composite_volume_get_member_stats(ocf_cache_t cache,
	struct kcas_get_stats *stats)
{
	int result;
	struct stats_ctx stats_ctx= {stats->core_id, stats->part_id,
		stats->composite_volume_member_id};
	if (stats->core_id == OCF_CORE_ID_INVALID &&
		stats->part_id == OCF_IO_CLASS_INVALID) {
		result = ocf_composite_volume_get_member_stats(cache, stats_ctx,
			&stats->blocks, _composite_volume_member_stats_cache);
	} else if (stats->part_id == OCF_IO_CLASS_INVALID) {
		result = ocf_composite_volume_get_member_stats(cache, stats_ctx,
			&stats->blocks, _composite_volume_member_stats_core);
	} else {
		if (stats->core_id == OCF_CORE_ID_INVALID) {
			result = ocf_composite_volume_get_member_stats(cache, stats_ctx,
				&stats->blocks, _composite_volume_member_stats_part_cache);
		} else {
			result = ocf_composite_volume_get_member_stats(cache, stats_ctx,
				&stats->blocks, _composite_volume_member_stats_part_core);
		}
	}
	return result;
}
#endif

int cache_mngt_get_stats(struct kcas_get_stats* stats)
{
	int result;
	ocf_cache_t cache;
	ocf_core_t core = NULL;

	result = mngt_get_cache_by_id(ctx, stats->cache_id, &cache);
	if (result)
		return result;

	result = _cache_mngt_read_lock_sync(cache);
	if (result)
		goto put;

#ifdef OCF_DEBUG_STATS
	if (stats->composite_volume_member_id != OCF_COMPOSITE_VOLUME_MEMBER_ID_INVALID){
		result = composite_volume_get_member_stats(cache, stats);
		if (result)
			goto put;
	} else
#endif
	if (stats->core_id == OCF_CORE_ID_INVALID &&
		stats->part_id == OCF_IO_CLASS_INVALID) {
		result = ocf_stats_collect_cache(cache, &stats->usage, &stats->req,
			&stats->blocks, &stats->errors);
		if (result)
			goto put;

	}
	else if (stats->part_id == OCF_IO_CLASS_INVALID) {
		result = get_core_by_id(cache, stats->core_id, &core);
		if (result)
			goto put;

		result = ocf_stats_collect_core(core, &stats->usage, &stats->req,
			&stats->blocks, &stats->errors);
		if (result)
			goto put;

	}
	else {
		if (stats->core_id == OCF_CORE_ID_INVALID) {
			result = ocf_stats_collect_part_cache(cache, stats->part_id,
				&stats->usage, &stats->req, &stats->blocks);
		}
		else {
			result = get_core_by_id(cache, stats->core_id, &core);
			if (result)
				goto put;

			result = ocf_stats_collect_part_core(core, stats->part_id,
				&stats->usage, &stats->req, &stats->blocks);
		}
	}

put:
	ocf_mngt_cache_put(cache);
	return result;
}
#ifndef OCF_DEBUG_STATS
int cache_mngt_reset_stats(const char* cache_name, size_t cache_name_len,
	const char* core_name, size_t core_name_len)
#else
int cache_mngt_reset_stats(const char* cache_name, size_t cache_name_len,
	const char* core_name, size_t core_name_len, int composite_volume_member_id)
#endif
{
	ocf_cache_t cache;
	ocf_core_t core;
	int result = 0;

	result = ocf_mngt_cache_get_by_name(ctx, cache_name, cache_name_len,
		&cache);
	if (result)
		return result;

	result = _cache_mngt_lock_sync(cache);
	if (result) {
		ocf_mngt_cache_put(cache);
		return result;
	}

	if (core_name) {
		result = ocf_core_get_by_name(cache, core_name,
			core_name_len, &core);
		if (result)
			goto out;

		ocf_core_stats_initialize(core);
#ifdef OCF_DEBUG_STATS
		result = ocf_composite_volume_stats_initialize(cache, core,
				composite_volume_member_id);
		if (result)
			goto out;
#endif
	}
	else {
		result = ocf_core_stats_initialize_all(cache);
#ifdef OCF_DEBUG_STATS
		if (result)
			goto out;
		result = ocf_composite_volume_stats_initialize_all_cores(cache,
				composite_volume_member_id);
#endif
	}

out:
	// ocf_mngt_cache_unlock(cache);
	ocf_mngt_cache_put(cache);
	return result;
}

__THROW int ioctl(int __fd, unsigned long int __request, void* args)
{
	int retval = FAILURE;

	switch (__request) {
	case KCAS_IOCTL_GET_STATS: {
		struct kcas_get_stats* cmd_info = (struct kcas_get_stats*)args;
		retval = cache_mngt_get_stats(cmd_info);
		sched_yield();
		break;
	}

	case KCAS_IOCTL_CACHE_INFO: {
		struct kcas_cache_info* cmd_info = (struct kcas_cache_info*)args;
		retval = cache_mngt_get_info(cmd_info);
		sched_yield();
		break;
	}

	case KCAS_IOCTL_RESET_STATS: {
		struct kcas_reset_stats* cmd_info = (struct kcas_reset_stats*)args;
		char cache_name[OCF_CACHE_NAME_SIZE];
		char core_name[OCF_CORE_NAME_SIZE];

		cache_name_from_id(cache_name, cmd_info->cache_id);

		if (cmd_info->core_id != OCF_CORE_ID_INVALID)
			core_name_from_id(core_name, cmd_info->core_id);

#ifndef OCF_DEBUG_STATS
		retval = cache_mngt_reset_stats(cache_name, OCF_CACHE_NAME_SIZE,
			cmd_info->core_id != OCF_CORE_ID_INVALID ?
			core_name : NULL,
			cmd_info->core_id != OCF_CORE_ID_INVALID ?
			OCF_CORE_NAME_SIZE : 0);
#else
		retval = cache_mngt_reset_stats(cache_name, OCF_CACHE_NAME_SIZE,
			cmd_info->core_id != OCF_CORE_ID_INVALID ?
			core_name : NULL,
			cmd_info->core_id != OCF_CORE_ID_INVALID ?
			OCF_CORE_NAME_SIZE : 0,
			cmd_info->composite_volume_member_id);
#endif
		break;
	}

	case KCAS_IOCTL_GET_CACHE_COUNT: {
		struct kcas_cache_count *cmd_info = args;

		cmd_info->cache_count = ocf_mngt_cache_get_count(ctx);
		retval = 0;
		break;
	}

	case KCAS_IOCTL_LIST_CACHE: {
		struct kcas_cache_list *cmd_info = args;

		retval = cache_mngt_list_caches(cmd_info);
		break;
	}

	default:
		break;
	}

	return retval;
}

int open_ctrl_device()
{
	// Need to return a valid fd but of a non-existing file because the code will use it to close the file
	// If we return 0 it closes the stdin and if -1 the open fails.
	return __INT_MAX__;
}

int close (int fd)
{
	if (fd != __INT_MAX__) close(fd);
	return 0;
}

int run_ioctl_interruptible(int fd, int command, void* cmd,
	char* friendly_name, int cache_id, int core_id)
{
	return 0;
}

int run_ioctl_interruptible_retry(int fd, int command, void* cmd,
	char* friendly_name, int cache_id, int core_id)
{
	return 0;
}

int run_ioctl(int fd, int command, void* cmd)
{
	return 0;
}

int create_pipe_pair(FILE** intermediate_file)
{
	/* 1 is writing end, 0 is reading end of a pipe */
	int pipefd[2];

	if (pipe(pipefd)) {
		cas_printf(LOG_ERR, "Failed to create unidirectional pipe.\n");
		return FAILURE;
	}

	intermediate_file[0] = fdopen(pipefd[0], "r");
	if (!intermediate_file[0]) {
		cas_printf(LOG_ERR, "Failed to open reading end of an unidirectional pipe.\n");
		close(pipefd[0]);
		close(pipefd[1]);
		return FAILURE;
	}
	intermediate_file[1] = fdopen(pipefd[1], "w");
	if (!intermediate_file[1]) {
		cas_printf(LOG_ERR, "Failed to open reading end of an unidirectional pipe.\n");
		fclose(intermediate_file[0]);
		close(pipefd[1]);
		return FAILURE;
	}
	return SUCCESS;
}
