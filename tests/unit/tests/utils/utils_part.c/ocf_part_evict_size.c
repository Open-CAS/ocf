/*
 * <tested_file_path>src/utils/utils_part.c</tested_file_path>
 * <tested_function>ocf_part_evict_size</tested_function>
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
#include "../ocf_cache_priv.h"
#include "../ocf_request.h"
#include "../metadata/metadata.h"
#include "../engine/cache_engine.h"
#include "../eviction/ops.h"
#include "utils_part.h"

#include "utils/utils_part.c/ocf_part_evict_size_generated_wraps.c"

uint32_t __wrap_ocf_part_get_max_size(ocf_cache_t cache,
		struct ocf_user_part *target_part)
{
	return mock();
}

uint32_t __wrap_ocf_engine_repart_count(struct ocf_request *req)
{
	return mock();
}

uint32_t __wrap_ocf_engine_unmapped_count(struct ocf_request *req)
{
	return mock();
}

uint32_t __wrap_ocf_part_get_occupancy(struct ocf_user_part *target_part)
{
	return mock();
}

ocf_cache_line_t __wrap_ocf_freelist_num_free(ocf_freelist_t freelist)
{
	return mock();
}

void __wrap_ocf_req_set_part_evict(struct ocf_request *req)
{
	function_called();
}

void __wrap_ocf_req_clear_part_evict(struct ocf_request *req)
{
	function_called();
}

static void ocf_part_evict_size_test01(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 0;
	uint32_t cachelines_to_map = 320;
	uint32_t part_occupied_cachelines = 512;
	uint32_t freelist_size = 500;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	print_test_description("Enough free space available");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	// Enough free cachelines to map a whole request
	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	assert_int_equal(ocf_part_evict_size(&req), 0);

	test_free(req.cache);
}

static void ocf_part_evict_size_test02(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 0;
	uint32_t cachelines_to_map = 320;
	uint32_t part_occupied_cachelines = 960;
	uint32_t freelist_size = 500;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t available_cachelines = max_part_size - part_occupied_cachelines;
	uint32_t cachelines_to_evict = cachelines_to_map - available_cachelines;

	print_test_description("Cache has enough free cachelines,"
		   " but target partition must be evicted");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	expect_function_call(__wrap_ocf_req_set_part_evict);

	assert_int_equal(ocf_part_evict_size(&req), cachelines_to_evict);

	test_free(req.cache);
}

static void ocf_part_evict_size_test03(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 320;
	uint32_t cachelines_to_map = 0;
	uint32_t part_occupied_cachelines = 512;
	uint32_t freelist_size = 0;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t cachelines_to_evict = 0;

	print_test_description("Only repart (no mapping). Freelist is empty but "
			"space in a target part is availabe,");
	print_test_description("\tso no cachelines should be "
			" evcited from cache");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	assert_int_equal(ocf_part_evict_size(&req), cachelines_to_evict);

	test_free(req.cache);
}

static void ocf_part_evict_size_test04(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 320;
	uint32_t cachelines_to_map = 0;
	uint32_t part_occupied_cachelines = 1100;
	uint32_t freelist_size = 0;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t cachelines_debt = part_occupied_cachelines - max_part_size;
	uint32_t cachelines_to_evict = cachelines_to_repart + cachelines_debt;

	print_test_description("Only repart (no mapping). Freelist is empty and no"
			" space in target part is availabe.");
	print_test_description("\tEvict only from target partition");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	expect_function_call(__wrap_ocf_req_set_part_evict);

	assert_int_equal(ocf_part_evict_size(&req), cachelines_to_evict);

	test_free(req.cache);
}

static void ocf_part_evict_size_test05(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 0;
	uint32_t cachelines_to_map = 320;
	uint32_t part_occupied_cachelines = 960;
	uint32_t freelist_size = 0;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t available_cachelines = max_part_size - part_occupied_cachelines;
	uint32_t cachelines_to_evict = cachelines_to_map - available_cachelines;

	print_test_description("Freelist is empty and no space in the target part "
			"is available");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	expect_function_call(__wrap_ocf_req_set_part_evict);

	assert_int_equal(ocf_part_evict_size(&req), cachelines_to_evict);

	test_free(req.cache);
}

static void ocf_part_evict_size_test06(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 0;
	uint32_t cachelines_to_map = 320;
	uint32_t part_occupied_cachelines = 320;
	uint32_t freelist_size = 0;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t available_cachelines = max_part_size - part_occupied_cachelines;
	uint32_t cachelines_to_evict = cachelines_to_map;

	print_test_description("Freelist is empty but target part has enough space");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	expect_function_call(__wrap_ocf_req_clear_part_evict);

	assert_int_equal(ocf_part_evict_size(&req), cachelines_to_evict);

	test_free(req.cache);
}

static void ocf_part_evict_size_test07(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 0;
	uint32_t cachelines_to_map = 320;
	uint32_t part_occupied_cachelines = 1280;
	uint32_t freelist_size = 0;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t debt_cachelines = part_occupied_cachelines - max_part_size;
	uint32_t cachelines_to_evict = cachelines_to_map + debt_cachelines;

	print_test_description("Freelist is empty and part occupancy exceeded");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	expect_function_call(__wrap_ocf_req_set_part_evict);

	assert_int_equal(ocf_part_evict_size(&req),
			(part_occupied_cachelines - max_part_size) + cachelines_to_map);

	test_free(req.cache);
}

static void ocf_part_evict_size_test08(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 320;
	uint32_t cachelines_to_map = 0;
	uint32_t part_occupied_cachelines = 1280;
	uint32_t freelist_size = 0;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t debt_cachelines = part_occupied_cachelines - max_part_size;
	uint32_t cachelines_to_evict = debt_cachelines + cachelines_to_repart;

	print_test_description("Target part occupancy limit is exceeded during "
			"repart");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	expect_function_call(__wrap_ocf_req_set_part_evict);

	assert_int_equal(ocf_part_evict_size(&req),
			(part_occupied_cachelines - max_part_size) + cachelines_to_repart);

	test_free(req.cache);
}

static void ocf_part_evict_size_test09(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 320;
	uint32_t cachelines_to_map = 0;
	uint32_t part_occupied_cachelines = 320;
	uint32_t freelist_size = 0;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t cachelines_to_evict = 0;

	print_test_description("Repart while target part has enough of available "
		   "space");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	assert_int_equal(ocf_part_evict_size(&req), cachelines_to_evict);

	test_free(req.cache);
}

static void ocf_part_evict_size_test10(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 0;
	uint32_t cachelines_to_map = 320;
	uint32_t part_occupied_cachelines = 320;
	uint32_t freelist_size = 320;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t cachelines_to_evict = 0;

	print_test_description("Enough of available cachelines in target part, "
			"freelist has exactly required number of free cachelines");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	assert_int_equal(ocf_part_evict_size(&req), cachelines_to_evict);

	test_free(req.cache);
}

static void ocf_part_evict_size_test11(void **state)
{
	uint32_t max_part_size = 1024;
	uint32_t cachelines_to_repart = 320;
	uint32_t cachelines_to_map = 0;
	uint32_t part_occupied_cachelines = 384;
	uint32_t freelist_size = 0;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t cachelines_to_evict = 0;

	print_test_description("Number of cachelines to repart is equal to number "
			"of cachelines available in the target partition");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	assert_int_equal(ocf_part_evict_size(&req), cachelines_to_evict);

	test_free(req.cache);
}

static void ocf_part_evict_size_test12(void **state)
{
	uint32_t max_part_size = 0;
	uint32_t cachelines_to_repart = 0;
	uint32_t cachelines_to_map = 320;
	uint32_t part_occupied_cachelines = 384;
	uint32_t freelist_size = 0;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t cachelines_to_evict =
		part_occupied_cachelines + cachelines_to_map;

	print_test_description("Freelist IS empty. Max occupancy set to 0, but "
			"some cachelines are still assigned to traget part - evict them");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	expect_function_call(__wrap_ocf_req_set_part_evict);

	assert_true(ocf_part_evict_size(&req) >= part_occupied_cachelines);

	test_free(req.cache);
}

static void ocf_part_evict_size_test13(void **state)
{
	uint32_t max_part_size = 0;
	uint32_t cachelines_to_repart = 0;
	uint32_t cachelines_to_map = 320;
	uint32_t part_occupied_cachelines = 384;
	uint32_t freelist_size = 1024;

	struct ocf_request req;
	req.cache = test_malloc(sizeof(struct ocf_cache));

	uint32_t cachelines_to_evict =
		part_occupied_cachelines + cachelines_to_map;

	print_test_description("Freelist IS NOT empty. Max occupancy set to 0, but"
			" some cachelines are still assigned to traget part - evict them");

	will_return(__wrap_ocf_part_get_max_size, max_part_size);

	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);
	will_return(__wrap_ocf_engine_repart_count, cachelines_to_repart);

	will_return(__wrap_ocf_part_get_occupancy, part_occupied_cachelines);

	will_return(__wrap_ocf_freelist_num_free, freelist_size);
	will_return(__wrap_ocf_engine_unmapped_count, cachelines_to_map);

	expect_function_call(__wrap_ocf_req_set_part_evict);

	assert_true(ocf_part_evict_size(&req) >= part_occupied_cachelines);

	test_free(req.cache);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_part_evict_size_test01),
		cmocka_unit_test(ocf_part_evict_size_test02),
		cmocka_unit_test(ocf_part_evict_size_test03),
		cmocka_unit_test(ocf_part_evict_size_test04),
		cmocka_unit_test(ocf_part_evict_size_test05),
		cmocka_unit_test(ocf_part_evict_size_test06),
		cmocka_unit_test(ocf_part_evict_size_test07),
		cmocka_unit_test(ocf_part_evict_size_test08),
		cmocka_unit_test(ocf_part_evict_size_test09),
		cmocka_unit_test(ocf_part_evict_size_test10),
		cmocka_unit_test(ocf_part_evict_size_test11),
		cmocka_unit_test(ocf_part_evict_size_test12),
		cmocka_unit_test(ocf_part_evict_size_test13)
	};

	print_message("Unit test for ocf_part_evict_size\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
