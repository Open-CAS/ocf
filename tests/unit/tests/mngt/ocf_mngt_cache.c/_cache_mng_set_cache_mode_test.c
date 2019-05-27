/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

//<tested_file_path>src/mngt/ocf_mngt_cache.c</tested_file_path>
//<tested_function>_cache_mng_set_cache_mode</tested_function>

/*
<functions_to_leave>
</functions_to_leave>
*/

#undef static
#undef inline

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "print_desc.h"

/*
 * Headers from tested target.
 */
#include "ocf/ocf.h"
#include "ocf_mngt_common.h"
#include "../ocf_core_priv.h"
#include "../ocf_queue_priv.h"
#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../utils/utils_part.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_device.h"
#include "../utils/utils_io.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_pipeline.h"
#include "../concurrency/ocf_concurrency.h"
#include "../eviction/ops.h"
#include "../ocf_ctx_priv.h"
#include "../cleaning/cleaning.h"

/*
 * Mocked functions
 */
bool __wrap_ocf_cache_mode_is_valid(ocf_cache_mode_t mode)
{
	function_called();
	return mock();
}

const char *__wrap_ocf_get_io_iface_name(ocf_cache_mode_t cache_mode)
{
}

ocf_ctx_t __wrap_ocf_cache_get_ctx(ocf_cache_t cache)
{
	return cache->owner;
}

int __wrap_ocf_log_raw(ocf_logger_t logger, ocf_logger_lvl_t lvl,
		const char *fmt, ...)
{
	function_called();
	return mock();
}

int __wrap_ocf_mngt_cache_flush(ocf_cache_t cache, bool interruption)
{
	function_called();
	return mock();
}

int __wrap_ocf_metadata_flush_superblock(struct ocf_cache *cache)
{
}

bool __wrap_env_bit_test(int nr, const volatile unsigned long *addr)
{
	function_called();
	return mock();
}

void __wrap_env_atomic_set(env_atomic *a, int i)
{
	function_called();
}

int __wrap_env_atomic_read(const env_atomic *a)
{
	function_called();
	return mock();
}

int __wrap_ocf_mngt_cache_reset_fallback_pt_error_counter(ocf_cache_t cache)
{
	function_called();
	return mock();
}

char *__wrap_ocf_cache_get_name(ocf_cache_t cache)
{
}

void __wrap__ocf_mngt_test_volume_initial_write(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap_ocf_mngt_test_volume_first_read(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_test_volume_discard(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_test_volume_second_read(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_cache_device(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_check_ram(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_load_properties(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_prepare_metadata(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_test_volume(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_load_superblock(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_init_instance(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_clean_pol(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_flush_metadata(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_discard(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_flush(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_shutdown_status(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_attach_post_init(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap_ocf_mngt_cache_stop_wait_metadata_io(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap_ocf_mngt_cache_stop_remove_cores(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap_ocf_mngt_cache_stop_unplug(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap_ocf_mngt_cache_stop_put_io_queues(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap_ocf_mngt_cache_detach_flush(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}


void ocf_mngt_cache_detach_stop_cache_io(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
}

void ocf_mngt_cache_detach_stop_cleaner_io(ocf_pipeline_t pipeline,
		void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap_ocf_mngt_cache_detach_wait_pending(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap_ocf_mngt_cache_detach_update_metadata(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap_ocf_mngt_cache_detach_unplug(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_test_volume_first_read(
		  ocf_pipeline_t pipeline, void *priv, ocf_pipeline_arg_t arg)
{
}

void __wrap__ocf_mngt_test_volume_finish(
		  ocf_pipeline_t pipeline, void *priv, int error)
{
}

void __wrap__ocf_mngt_cache_attach_finish(
		  ocf_pipeline_t pipeline, void *priv, int error)
{
}

void __wrap_ocf_mngt_cache_stop_finish(
		  ocf_pipeline_t pipeline, void *priv, int error)
{
}

void __wrap_ocf_mngt_cache_detach_finish(
		  ocf_pipeline_t pipeline, void *priv, int error)
{
}

void __wrap_ocf_mngt_cache_save_finish(
		  ocf_pipeline_t pipeline, void *priv, int error)
{
}

static void _cache_mng_set_cache_mode_test01(void **state)
{
	ocf_cache_mode_t mode_old = -20;
	ocf_cache_mode_t mode_new = ocf_cache_mode_none;
	struct ocf_ctx ctx = {
		.logger = 0x1, /* Just not NULL, we don't care. */
	};
	struct ocf_superblock_config sb_config = {
		.cache_mode = mode_old,
	};
	struct ocf_cache cache = {
		.owner = &ctx,
		.conf_meta = &sb_config,
	};
	int result;

	print_test_description("Invalid new mode produces appropirate error code");

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 0);

	result = _cache_mng_set_cache_mode(&cache, mode_new);

	assert_int_equal(result, -OCF_ERR_INVAL);
	assert_int_equal(cache.conf_meta->cache_mode, mode_old);
}

static void _cache_mng_set_cache_mode_test02(void **state)
{
	ocf_cache_mode_t mode_old = ocf_cache_mode_wt;
	ocf_cache_mode_t mode_new = ocf_cache_mode_wt;
	struct ocf_ctx ctx = {
		.logger = 0x1, /* Just not NULL, we don't care. */
	};
	struct ocf_superblock_config sb_config = {
		.cache_mode = mode_old,
	};
	struct ocf_cache cache = {
		.owner = &ctx,
		.conf_meta = &sb_config,
	};
	uint8_t flush = 0;
	int result;

	print_test_description("Attempt to set mode the same as previous");

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 1);

	expect_function_call(__wrap_ocf_log_raw);
	will_return(__wrap_ocf_log_raw, 0);

	result = _cache_mng_set_cache_mode(&cache, mode_new);

	assert_int_equal(result, 0);
	assert_int_equal(cache.conf_meta->cache_mode, mode_old);
}

static void _cache_mng_set_cache_mode_test03(void **state)
{
	ocf_cache_mode_t mode_old = ocf_cache_mode_wb;
	ocf_cache_mode_t mode_new = ocf_cache_mode_wa;
	struct ocf_ctx ctx = {
		.logger = 0x1, /* Just not NULL, we don't care. */
	};
	struct ocf_superblock_config sb_config = {
		.cache_mode = mode_old,
	};
	struct ocf_cache cache = {
		.owner = &ctx,
		.conf_meta = &sb_config,
	};
	int result;
	int i;

	print_test_description("Old cache mode is write back. "
		       "Setting new cache mode is succesfull");

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 1);

	for(i = 0; i != OCF_CORE_MAX; ++i) {
		expect_function_call(__wrap_env_bit_test);
		will_return(__wrap_env_bit_test, 1);

		expect_function_call(__wrap_env_atomic_read);
		will_return(__wrap_env_atomic_read, 1);
		expect_function_call(__wrap_env_atomic_set);
	}

	expect_function_call(__wrap_ocf_log_raw);
	will_return(__wrap_ocf_log_raw, 0);

	result = _cache_mng_set_cache_mode(&cache, mode_new);

	assert_int_equal(result, 0);
	assert_int_equal(cache.conf_meta->cache_mode, mode_new);
}

static void _cache_mng_set_cache_mode_test04(void **state)
{
	ocf_cache_mode_t mode_old = ocf_cache_mode_wt;
	ocf_cache_mode_t mode_new = ocf_cache_mode_wa;
	struct ocf_ctx ctx = {
		.logger = 0x1, /* Just not NULL, we don't care. */
	};
	struct ocf_superblock_config sb_config = {
		.cache_mode = mode_old,
	};
	struct ocf_cache cache = {
		.owner = &ctx,
		.conf_meta = &sb_config,
	};
	int result;
	int i;

	print_test_description("Mode changed successfully");

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 1);

	expect_function_call(__wrap_ocf_log_raw);
	will_return(__wrap_ocf_log_raw, 0);

	result = _cache_mng_set_cache_mode(&cache, mode_new);

	assert_int_equal(result, 0);
	assert_int_equal(cache.conf_meta->cache_mode, mode_new);
}

/*
 * Main function. It runs tests.
 */
int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(_cache_mng_set_cache_mode_test01),
		cmocka_unit_test(_cache_mng_set_cache_mode_test02),
		cmocka_unit_test(_cache_mng_set_cache_mode_test03),
		cmocka_unit_test(_cache_mng_set_cache_mode_test04),
	};

	print_message("Unit test of _cache_mng_set_cache_mode\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
