/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

/*
 * <tested_file_path>src/mngt/ocf_mngt_io_class.c</tested_file_path>
 * <tested_function>ocf_mngt_cache_io_classes_configure</tested_function>
 * <functions_to_leave>
 *	INSERT HERE LIST OF FUNCTIONS YOU WANT TO LEAVE
 *	ONE FUNCTION PER LINE
 *  _ocf_mngt_io_class_edit
 *  _ocf_mngt_io_class_configure
 *  _ocf_mngt_io_class_remove
 * </functions_to_leave>
 */

#undef static

#undef inline


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "print_desc.h"

#include "ocf/ocf.h"
#include "ocf_mngt_common.h"
#include "../ocf_priv.h"
#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../utils/utils_part.h"
#include "../eviction/ops.h"
#include "ocf_env.h"

/* Mocks reqired for compilation */
int __wrap_ocf_log_raw(const struct ocf_logger *logger, ocf_logger_lvl_t lvl,
		const char *fmt, ...)
{
}

ocf_ctx_t __wrap_ocf_cache_get_ctx(ocf_cache_t cache)
{
}

char *__wrap_ocf_cache_get_name(ocf_cache_t cache)
{
}

int __wrap_ocf_mngt_cache_lock(ocf_cache_t cache)
{
	return 0;
}

void __wrap_ocf_mngt_cache_unlock(ocf_cache_t cache)
{
}

void __wrap_ocf_metadata_lock(struct ocf_cache *cache, int rw)
{
}

void __wrap_ocf_metadata_unlock(struct ocf_cache *cache, int rw)
{
}

/* Functions mocked for testing purposes */
bool __wrap_ocf_part_is_added(struct ocf_user_part *part)
{
	function_called();
	return mock();
}

int __wrap__ocf_mngt_set_partition_size(struct ocf_cache *cache,
		ocf_part_id_t part_id, uint32_t min, uint32_t max)
{
	function_called();
	return mock();
}

void __wrap_ocf_part_set_prio(struct ocf_cache *cache,
		struct ocf_user_part *part, int16_t prio)
{
	function_called();
}

bool __wrap_ocf_part_is_valid(struct ocf_user_part *part)
{
	function_called();
	return mock();
}


void __wrap_ocf_part_set_valid(struct ocf_cache *cache, ocf_part_id_t id,
		bool valid)
{
	function_called();
	check_expected(valid);
	check_expected(id);
}

int __wrap__ocf_mngt_io_class_validate_cfg(ocf_cache_t cache,
		const struct ocf_mngt_io_class_config *cfg)
{
	function_called();
	return mock();
}

void __wrap_ocf_part_sort(struct ocf_cache *cache)
{
	function_called();
}

int __wrap_ocf_metadata_flush_superblock(struct ocf_cache *cache)
{
	function_called();
	return mock();
}

/* Helper function for test prepration */
static inline void setup_valid_config(struct ocf_mngt_io_class_config *cfg,
		bool remove)
{
	int i;
	for (i = 0; i < OCF_IO_CLASS_MAX; i++) {
		cfg[i].class_id = i;
		cfg[i].name = remove ? NULL : "test_io_class_name" ;
		cfg[i].prio = i;
		cfg[i].cache_mode = ocf_cache_mode_pt;
		cfg[i].min_size = 2*i;
		cfg[i].max_size = 20*i;
	}
}

static void ocf_mngt_io_classes_configure_test03(void **state)
{
	struct ocf_cache cache = {0};
	struct ocf_mngt_io_classes_config cfg = {0};
	int result, i;

	for (i = 0; i < OCF_IO_CLASS_MAX; i++) {
		cache.user_parts[i].config =
				test_malloc(sizeof(struct ocf_user_part_config));
	}
	cache.device = 1;

	setup_valid_config(cfg.config, true);

	print_test_description("Remove all io classes");

	for (i = 0; i < OCF_IO_CLASS_MAX; i++) {
		expect_function_call(__wrap__ocf_mngt_io_class_validate_cfg);
		will_return(__wrap__ocf_mngt_io_class_validate_cfg, 0);
	}

	/* Removing default io_class is not allowed */
	for (i = 1; i < OCF_IO_CLASS_MAX; i++) {
		expect_function_call(__wrap_ocf_part_is_valid);
		will_return(__wrap_ocf_part_is_valid, 1);

		expect_function_call(__wrap_ocf_part_set_valid);
		/* Test assumes default partition has id equal 0 */
		expect_in_range(__wrap_ocf_part_set_valid, id, OCF_IO_CLASS_ID_MIN + 1,
				OCF_IO_CLASS_ID_MAX);
		expect_value(__wrap_ocf_part_set_valid, valid, false);
	}

	expect_function_call(__wrap_ocf_part_sort);

	expect_function_call(__wrap_ocf_metadata_flush_superblock);
	will_return(__wrap_ocf_metadata_flush_superblock, 0);

	result = ocf_mngt_cache_io_classes_configure(&cache, &cfg);

	assert_int_equal(result, 0);

	for (i = 0; i < OCF_IO_CLASS_MAX; i++)
		test_free(cache.user_parts[i].config);
}

static void ocf_mngt_io_classes_configure_test02(void **state)
{
	struct ocf_cache cache = {0};
	struct ocf_mngt_io_classes_config cfg = {0};
	int result, i;

	for (i = 0; i < OCF_IO_CLASS_MAX; i++) {
		cache.user_parts[i].config =
				test_malloc(sizeof(struct ocf_user_part_config));
	}
	cache.device = 1;

	setup_valid_config(cfg.config, false);

	print_test_description("Configure all possible io classes");

	for (i = 0; i < OCF_IO_CLASS_MAX; i++) {
		expect_function_call(__wrap__ocf_mngt_io_class_validate_cfg);
		will_return(__wrap__ocf_mngt_io_class_validate_cfg, 0);
	}

	/* Configure default io_class */
	expect_function_call(__wrap_ocf_part_is_added);
	will_return(__wrap_ocf_part_is_added, 1);

	expect_function_call(__wrap__ocf_mngt_set_partition_size);
	will_return(__wrap__ocf_mngt_set_partition_size, 0);

	expect_function_call(__wrap_ocf_part_set_prio);

	/* Configure custom io_classes */
	for (i = 1; i < OCF_IO_CLASS_MAX; i++) {
		expect_function_call(__wrap_ocf_part_is_added);
		will_return(__wrap_ocf_part_is_added, 1);

		expect_function_call(__wrap__ocf_mngt_set_partition_size);
		will_return(__wrap__ocf_mngt_set_partition_size, 0);

		expect_function_call(__wrap_ocf_part_is_valid);
		will_return(__wrap_ocf_part_is_valid, 0);

		expect_function_call(__wrap_ocf_part_set_valid);
		expect_in_range(__wrap_ocf_part_set_valid, id, OCF_IO_CLASS_ID_MIN,
				OCF_IO_CLASS_ID_MAX);
		expect_value(__wrap_ocf_part_set_valid, valid, true);

		expect_function_call(__wrap_ocf_part_set_prio);
	}

	expect_function_call(__wrap_ocf_part_sort);

	expect_function_call(__wrap_ocf_metadata_flush_superblock);
	will_return(__wrap_ocf_metadata_flush_superblock, 0);

	result = ocf_mngt_cache_io_classes_configure(&cache, &cfg);

	assert_int_equal(result, 0);

	for (i = 0; i < OCF_IO_CLASS_MAX; i++)
		test_free(cache.user_parts[i].config);
}

static void ocf_mngt_io_classes_configure_test01(void **state)
{
	struct ocf_cache cache;
	struct ocf_mngt_io_classes_config cfg[OCF_IO_CLASS_MAX];
	int error_code = -OCF_ERR_INVAL;
	int result;

	print_test_description("Invalid config - "
		   "termination with error");

	expect_function_call(__wrap__ocf_mngt_io_class_validate_cfg);
	will_return(__wrap__ocf_mngt_io_class_validate_cfg, error_code);

	result = ocf_mngt_cache_io_classes_configure(&cache, &cfg);

	assert_int_equal(result, error_code);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_mngt_io_classes_configure_test01),
		cmocka_unit_test(ocf_mngt_io_classes_configure_test02),
		cmocka_unit_test(ocf_mngt_io_classes_configure_test03)
	};

	print_message("Unit test of src/mngt/ocf_mngt_io_class.c");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
