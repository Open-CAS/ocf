/*
 * <tested_file_path>src/engine/engine_common.c</tested_file_path>
 * <tested_function>ocf_prepare_clines_hit</tested_function>
 * <functions_to_leave>
 *	INSERT HERE LIST OF FUNCTIONS YOU WANT TO LEAVE
 *	ONE FUNCTION PER LINE
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

void __wrap_ocf_req_hash_unlock_rd(struct ocf_request *req)
{
}

uint32_t __wrap_ocf_part_check_space(struct ocf_request *req,
		uint32_t *to_evict)
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

int __wrap_space_managment_evict_do(struct ocf_cache *cache,
		struct ocf_request *req, uint32_t evict_cline_no)
{
	return mock();
}

bool __wrap_ocf_part_is_enabled(struct ocf_user_part *target_part)
{
	return mock();
}

bool __wrap_ocf_engine_needs_repart(struct ocf_request *req)
{
	return mock();
}

void __wrap_ocf_req_set_mapping_error(struct ocf_request *req)
{
	function_called();
}

static void ocf_prepare_clines_hit_test01(void **state)
{
	struct ocf_request req = {};
	print_test_description("Request is hit and part is enabled\n");
	will_return(__wrap_ocf_part_is_enabled, true);
	will_return(__wrap_ocf_engine_needs_repart, false);

	will_return(__wrap_lock_clines, 0);
	expect_function_call(__wrap_lock_clines);

	assert_int_equal(ocf_prepare_clines_hit(&req, NULL), 0);
}

static void ocf_prepare_clines_hit_test02(void **state)
{
	struct ocf_request req = {};
	print_test_description("Request is hit but part is disabled - tigger eviction\n");
	will_return(__wrap_ocf_part_is_enabled, false);

	will_return(__wrap_ocf_part_check_space, OCF_PART_IS_DISABLED);

	expect_function_call(__wrap_ocf_req_set_mapping_error);

	assert_int_equal(ocf_prepare_clines_hit(&req, NULL), -OCF_ERR_NO_LOCK);
}

static void ocf_prepare_clines_hit_test03(void **state)
{
	struct ocf_request req = {};
	print_test_description("Request needs repart, part has enough of a free space\n");
	will_return(__wrap_ocf_part_is_enabled, true);
	will_return(__wrap_ocf_engine_needs_repart, true);

	will_return(__wrap_ocf_part_check_space, OCF_PART_HAS_SPACE);

	expect_function_call(__wrap_lock_clines);
	will_return(__wrap_lock_clines, 0);

	assert_int_equal(ocf_prepare_clines_hit(&req, NULL), 0);
}

static void ocf_prepare_clines_hit_test04(void **state)
{
	struct ocf_request req = {};
	print_test_description("Request needs repart, eviction fails\n");
	will_return(__wrap_ocf_part_is_enabled, true);
	will_return(__wrap_ocf_engine_needs_repart, true);

	will_return(__wrap_ocf_part_check_space, OCF_PART_IS_FULL);

	will_return(__wrap_ocf_part_check_space, OCF_PART_IS_FULL);
	will_return(__wrap_space_managment_evict_do, LOOKUP_MISS);
	expect_function_call(__wrap_ocf_req_set_mapping_error);

	assert_int_equal(ocf_prepare_clines_hit(&req, NULL), -OCF_ERR_NO_LOCK);
}

static void ocf_prepare_clines_hit_test05(void **state)
{
	struct ocf_request req = {};
	print_test_description("Request needs repart, eviction passed, no lock\n");

	will_return(__wrap_ocf_part_is_enabled, true);
	will_return(__wrap_ocf_engine_needs_repart, true);

	will_return(__wrap_ocf_part_check_space, OCF_PART_IS_FULL);

	will_return(__wrap_ocf_part_check_space, OCF_PART_IS_FULL);
	will_return(__wrap_space_managment_evict_do, LOOKUP_HIT);

	expect_function_call(__wrap_lock_clines);
	will_return(__wrap_lock_clines, OCF_ERR_NO_LOCK);

	will_return(__wrap_ocf_part_is_enabled, true);

	assert_int_equal(ocf_prepare_clines_hit(&req, NULL), OCF_ERR_NO_LOCK);
}

static void ocf_prepare_clines_hit_test06(void **state)
{
	struct ocf_request req = {};
	print_test_description("Partition is disabled, but has some cachelines assigned.\n");
	print_test_description("Trigger eviction and but don't lock cachelines\n");

	will_return(__wrap_ocf_part_is_enabled, false);

	will_return(__wrap_ocf_part_check_space, OCF_PART_IS_FULL);

	will_return(__wrap_ocf_part_check_space, OCF_PART_IS_FULL);
	will_return(__wrap_space_managment_evict_do, LOOKUP_HIT);

	will_return(__wrap_ocf_part_is_enabled, false);
	expect_function_call(__wrap_ocf_req_set_mapping_error);

	assert_int_equal(ocf_prepare_clines_hit(&req, NULL), -OCF_ERR_NO_LOCK);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_prepare_clines_hit_test01),
		cmocka_unit_test(ocf_prepare_clines_hit_test02),
		cmocka_unit_test(ocf_prepare_clines_hit_test03),
		cmocka_unit_test(ocf_prepare_clines_hit_test04),
		cmocka_unit_test(ocf_prepare_clines_hit_test05),
		cmocka_unit_test(ocf_prepare_clines_hit_test06)
	};

	print_message("Unit test for ocf_prepare_clines_hit\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
