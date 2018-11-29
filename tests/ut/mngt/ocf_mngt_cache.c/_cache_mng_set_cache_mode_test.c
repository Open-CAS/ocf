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
#include "../ocf_utils.h"
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
}

int __wrap_ocf_log_raw(const struct ocf_logger *logger, ocf_logger_lvl_t lvl,
		const char *fmt, ...)
{
	function_called();
	return mock();
}

int __wrap_ocf_mngt_cache_flush_nolock(ocf_cache_t cache, bool interruption)
{
	function_called();
	return mock();
}

int __wrap_ocf_metadata_flush_superblock(struct ocf_cache *cache)
{
	function_called();
	return mock();
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

static void _cache_mng_set_cache_mode_test01(void **state)
{
	int result;
	struct ocf_cache cache;
	ocf_cache_mode_t mode_old, mode_new;
	uint8_t flush;

	print_test_description("Invalid new mode produces appropirate error code");

	cache.conf_meta = test_malloc(sizeof(struct ocf_superblock_config));
	mode_old = -20;
	cache.conf_meta->cache_mode = mode_old;
	mode_new = ocf_cache_mode_none;
	flush = 0;

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 0);

	result = _cache_mng_set_cache_mode(&cache, mode_new, flush);

	assert_int_equal(result, -OCF_ERR_INVAL);
	assert_int_equal(cache.conf_meta->cache_mode, mode_old);

	test_free(cache.conf_meta);
}

static void _cache_mng_set_cache_mode_test02(void **state)
{
	int result;
	struct ocf_cache cache;
	ocf_cache_mode_t mode_old, mode_new;
	uint8_t flush;

	print_test_description("Attempt to set mode the same as previous");

	mode_old = mode_new = ocf_cache_mode_wt;
	flush = 0;

	cache.conf_meta = test_malloc(sizeof(struct ocf_superblock_config));
	cache.conf_meta->cache_mode = mode_old;

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 1);

	expect_function_call(__wrap_ocf_log_raw);
	will_return(__wrap_ocf_log_raw, 0);

	result = _cache_mng_set_cache_mode(&cache, mode_new, flush);

	assert_int_equal(result, 0);
	assert_int_equal(cache.conf_meta->cache_mode, mode_old);

	test_free(cache.conf_meta);
}

static void _cache_mng_set_cache_mode_test03(void **state)
{
	int result;
	struct ocf_cache cache;
	ocf_cache_mode_t mode_old, mode_new;
	uint8_t flush;

	print_test_description("Flush flag is set, but operation failed -"
		       " check if error code is correct");

	mode_old = ocf_cache_mode_wt;
	mode_new = ocf_cache_mode_pt;
	cache.conf_meta->cache_mode = mode_old;
	flush = 1;

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 1);

	expect_function_call(__wrap_ocf_mngt_cache_flush_nolock);
	will_return(__wrap_ocf_mngt_cache_flush_nolock, -OCF_ERR_NO_MEM);

	result = _cache_mng_set_cache_mode(&cache, mode_new, flush);

	assert_int_equal(result, -OCF_ERR_NO_MEM);
	assert_int_equal(cache.conf_meta->cache_mode, mode_old);
}

static void _cache_mng_set_cache_mode_test04(void **state)
{
	int result;
	struct ocf_cache cache;
	ocf_cache_mode_t mode_old, mode_new;
	uint8_t flush;
	int i;

	print_test_description("Flush flag is not set, "
		       "old cache mode is write back. "
		       "Setting new cache mode is succesfull");

	mode_old = ocf_cache_mode_wb;
	mode_new = ocf_cache_mode_wa;
	flush = 0;

	cache.conf_meta = test_malloc(sizeof(struct ocf_superblock_config));
	cache.conf_meta->cache_mode = mode_old;

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 1);

	for(i = 0; i != OCF_CORE_MAX; ++i) {
		expect_function_call(__wrap_env_bit_test);
		will_return(__wrap_env_bit_test, 1);

		expect_function_call(__wrap_env_atomic_read);
		will_return(__wrap_env_atomic_read, 1);
		expect_function_call(__wrap_env_atomic_set);
	}

	expect_function_call(__wrap_ocf_metadata_flush_superblock);
	will_return(__wrap_ocf_metadata_flush_superblock, 0);

	expect_function_call(__wrap_ocf_log_raw);
	will_return(__wrap_ocf_log_raw, 0);

	result = _cache_mng_set_cache_mode(&cache, mode_new, flush);

	assert_int_equal(result, 0);
	assert_int_equal(cache.conf_meta->cache_mode, mode_new);

	test_free(cache.conf_meta);
}

static void _cache_mng_set_cache_mode_test05(void **state)
{
	int result;
	struct ocf_cache cache;
	ocf_cache_mode_t mode_old, mode_new;
	uint8_t flush;
	int i;

	print_test_description("Flush flag is not set, "
		       "flushing metadata superblock fails");

	mode_old = ocf_cache_mode_wt;
	mode_new = ocf_cache_mode_wa;
	flush = 0;

	cache.conf_meta = test_malloc(sizeof(struct ocf_superblock_config));
	cache.conf_meta->cache_mode = mode_old;

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 1);

	expect_function_call(__wrap_ocf_metadata_flush_superblock);
	will_return(__wrap_ocf_metadata_flush_superblock, 1);

	expect_function_call(__wrap_ocf_log_raw);
	will_return(__wrap_ocf_log_raw, 0);

	result = _cache_mng_set_cache_mode(&cache, mode_new, flush);

	assert_int_equal(result, -OCF_ERR_WRITE_CACHE);
	assert_int_equal(cache.conf_meta->cache_mode, mode_old);

	test_free(cache.conf_meta);
}

static void _cache_mng_set_cache_mode_test06(void **state)
{
	int result;
	struct ocf_cache cache;
	ocf_cache_mode_t mode_old, mode_new;
	uint8_t flush;
	int i;

	print_test_description("No flush, mode changed successfully");
	mode_old = ocf_cache_mode_wt;
	mode_new = ocf_cache_mode_wa;
	flush = 0;

	cache.conf_meta = test_malloc(sizeof(struct ocf_superblock_config));
	cache.conf_meta->cache_mode = mode_old;

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 1);

	expect_function_call(__wrap_ocf_metadata_flush_superblock);
	will_return(__wrap_ocf_metadata_flush_superblock, 0);

	expect_function_call(__wrap_ocf_log_raw);
	will_return(__wrap_ocf_log_raw, 0);

	result = _cache_mng_set_cache_mode(&cache, mode_new, flush);

	assert_int_equal(result, 0);
	assert_int_equal(cache.conf_meta->cache_mode, mode_new);

	test_free(cache.conf_meta);
}

static void _cache_mng_set_cache_mode_test07(void **state)
{
	int result;
	struct ocf_cache cache;
	ocf_cache_mode_t mode_old, mode_new;
	uint8_t flush;
	int i;

	print_test_description("Flush performed, mode changed successfully");
	mode_old = ocf_cache_mode_wt;
	mode_new = ocf_cache_mode_wa;
	flush = 1;

	cache.conf_meta = test_malloc(sizeof(struct ocf_superblock_config));
	cache.conf_meta->cache_mode = mode_old;

	expect_function_call(__wrap_ocf_cache_mode_is_valid);
	will_return(__wrap_ocf_cache_mode_is_valid, 1);

	expect_function_call(__wrap_ocf_mngt_cache_flush_nolock);
	will_return(__wrap_ocf_mngt_cache_flush_nolock, 0);

	expect_function_call(__wrap_ocf_metadata_flush_superblock);
	will_return(__wrap_ocf_metadata_flush_superblock, 0);

	expect_function_call(__wrap_ocf_log_raw);
	will_return(__wrap_ocf_log_raw, 0);

	result = _cache_mng_set_cache_mode(&cache, mode_new, flush);

	assert_int_equal(result, 0);
	assert_int_equal(cache.conf_meta->cache_mode, mode_new);

	test_free(cache.conf_meta);
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
		cmocka_unit_test(_cache_mng_set_cache_mode_test05),
		cmocka_unit_test(_cache_mng_set_cache_mode_test06),
		cmocka_unit_test(_cache_mng_set_cache_mode_test07)
	};

	print_message("Unit test of _cache_mng_set_cache_mode\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
