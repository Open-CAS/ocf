/*
 * <tested_file_path>src/engine/engine_common.c</tested_file_path>
 * <tested_function>ocf_prepare_clines_miss</tested_function>
 * <functions_to_leave>
 *    ocf_prepare_clines_evict
 *    ocf_engine_evict
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
#include "../ocf_priv.h"
#include "../ocf_cache_priv.h"
#include "../ocf_queue_priv.h"
#include "../ocf_freelist.h"
#include "engine_common.h"
#include "engine_debug.h"
#include "../utils/utils_cache_line.h"
#include "../ocf_request.h"
#include "../utils/utils_cleaner.h"
#include "../utils/utils_part.h"
#include "../metadata/metadata.h"
#include "../eviction/eviction.h"
#include "../promotion/promotion.h"
#include "../concurrency/ocf_concurrency.h"

#include "engine/engine_common.c/prepare_clines_miss_generated_wraps.c"

struct ocf_cache_line_concurrency *__wrap_ocf_cache_line_concurrency(ocf_cache_t cache)
{
	return NULL;
}

void __wrap_ocf_req_hash_lock_upgrade(struct ocf_request *req)
{
}

void __wrap_ocf_req_hash_unlock_wr(struct ocf_request *req)
{
}

uint32_t __wrap_ocf_part_has_space(struct ocf_request *req)
{
	return mock();
}

int __wrap_lock_clines(struct ocf_request *req,
		const struct ocf_engine_callbacks *engine_cbs)
{
	function_called();
	return mock();
}

void __wrap_ocf_metadata_start_exclusive_access(
		struct ocf_metadata_lock *metadata_lock)
{
}

void __wrap_ocf_metadata_end_exclusive_access(
		struct ocf_metadata_lock *metadata_lock)
{
}

bool __wrap_ocf_part_is_enabled(struct ocf_user_part *target_part)
{
	return mock();
}

void __wrap_ocf_engine_map(struct ocf_request *req)
{
	function_called();
}

bool __wrap_ocf_req_test_mapping_error(struct ocf_request *req)
{
	return mock();
}

void __wrap_ocf_req_set_mapping_error(struct ocf_request *req)
{
	function_called();
}

int __wrap_space_managment_evict_do(struct ocf_request *req)
{
	function_called();
	return mock();
}

uint32_t __wrap_ocf_engine_unmapped_count(struct ocf_request *req)
{
	return 100;
}

static void ocf_prepare_clines_miss_test01(void **state)
{
	struct ocf_cache cache;
	struct ocf_request req = {.cache = &cache };
	print_test_description("Target part is disabled and empty\n");
	will_return(__wrap_ocf_part_is_enabled, false);
	expect_function_call(__wrap_ocf_req_set_mapping_error);
	assert_int_equal(ocf_prepare_clines_miss(&req, NULL), -OCF_ERR_NO_LOCK);
}

static void ocf_prepare_clines_miss_test02(void **state)
{
	struct ocf_cache cache;
	struct ocf_request req = {.cache = &cache };

	print_test_description("Target part is disabled but has cachelines assigned.\n");
	print_test_description("\tMark mapping error\n");

	will_return(__wrap_ocf_part_is_enabled, false);
	expect_function_call(__wrap_ocf_req_set_mapping_error);

	assert_int_equal(ocf_prepare_clines_miss(&req, NULL), -OCF_ERR_NO_LOCK);
}

static void ocf_prepare_clines_miss_test03(void **state)
{
	struct ocf_cache cache;
	struct ocf_request req = {.cache = &cache };

	print_test_description("Target part is enabled but doesn't have enough space.\n");
	print_test_description("\tEviction is ok and cachelines lock is acquired.\n");

	will_return(__wrap_ocf_part_is_enabled, true);
	will_return_always(__wrap_ocf_part_has_space, false);
	expect_function_call(__wrap_space_managment_evict_do);
	will_return_always(__wrap_space_managment_evict_do, LOOKUP_INSERTED);

	will_return_always(__wrap_ocf_req_test_mapping_error, false);

	will_return(__wrap_lock_clines, 0);
	expect_function_call(__wrap_lock_clines);

	assert_int_equal(ocf_prepare_clines_miss(&req, NULL), 0);
}

static void ocf_prepare_clines_miss_test04(void **state)
{
	struct ocf_cache cache;
	struct ocf_request req = {.cache = &cache };

	print_test_description("Target part is enabled but doesn't have enough space.\n");
	print_test_description("\tEviction failed\n");

	will_return(__wrap_ocf_part_is_enabled, true);
	will_return_always(__wrap_ocf_part_has_space, false);

	expect_function_call(__wrap_space_managment_evict_do);
	will_return(__wrap_space_managment_evict_do, LOOKUP_MISS);
	expect_function_call(__wrap_ocf_req_set_mapping_error);
	will_return_always(__wrap_ocf_req_test_mapping_error, true);

	assert_int_equal(ocf_prepare_clines_miss(&req, NULL), -OCF_ERR_NO_LOCK);
}

static void ocf_prepare_clines_miss_test06(void **state)
{
	struct ocf_cache cache;
	struct ocf_request req = {.cache = &cache };

	print_test_description("Target part is enabled but doesn't have enough space.\n");
	print_test_description("Eviction and mapping were ok, but failed to lock cachelines.\n");

	will_return_always(__wrap_ocf_part_has_space, false);

	expect_function_call(__wrap_space_managment_evict_do);
	will_return(__wrap_space_managment_evict_do, LOOKUP_HIT);

	will_return(__wrap_ocf_part_is_enabled, true);
	will_return_always(__wrap_ocf_req_test_mapping_error, false);

	expect_function_call(__wrap_lock_clines);
	will_return(__wrap_lock_clines, -OCF_ERR_NO_LOCK);

	expect_function_call(__wrap_ocf_req_set_mapping_error);

	assert_int_equal(ocf_prepare_clines_miss(&req, NULL), -OCF_ERR_NO_LOCK);
}

static void ocf_prepare_clines_miss_test07(void **state)
{
	struct ocf_cache cache;
	struct ocf_request req = {.cache = &cache };

	print_test_description("Target part is enabled but doesn't have enough space.\n");
	print_test_description("Eviction and mapping were ok, lock not acquired.\n");

	will_return_always(__wrap_ocf_part_has_space, false);

	expect_function_call(__wrap_space_managment_evict_do);
	will_return(__wrap_space_managment_evict_do, LOOKUP_HIT);

	will_return(__wrap_ocf_part_is_enabled, true);

	will_return_always(__wrap_ocf_req_test_mapping_error, false);

	expect_function_call(__wrap_lock_clines);
	will_return(__wrap_lock_clines, OCF_LOCK_NOT_ACQUIRED);

	assert_int_equal(ocf_prepare_clines_miss(&req, NULL), OCF_LOCK_NOT_ACQUIRED);
}

static void ocf_prepare_clines_miss_test08(void **state)
{
	struct ocf_cache cache;
	struct ocf_request req = {.cache = &cache };

	print_test_description("Target part is enabled has enough space.\n");
	print_test_description("\tMapping and cacheline lock are both ok\n");

	will_return(__wrap_ocf_part_is_enabled, true);
	will_return_always(__wrap_ocf_part_has_space, true);

	expect_function_call(__wrap_ocf_engine_map);
	will_return_always(__wrap_ocf_req_test_mapping_error, false);

	expect_function_call(__wrap_lock_clines);
	will_return(__wrap_lock_clines, OCF_LOCK_ACQUIRED);

	assert_int_equal(ocf_prepare_clines_miss(&req, NULL), OCF_LOCK_ACQUIRED);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_prepare_clines_miss_test01),
		cmocka_unit_test(ocf_prepare_clines_miss_test02),
		cmocka_unit_test(ocf_prepare_clines_miss_test03),
		cmocka_unit_test(ocf_prepare_clines_miss_test04),
		cmocka_unit_test(ocf_prepare_clines_miss_test06),
		cmocka_unit_test(ocf_prepare_clines_miss_test07),
		cmocka_unit_test(ocf_prepare_clines_miss_test08)
	};

	print_message("Unit test for ocf_prepare_clines_miss\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
