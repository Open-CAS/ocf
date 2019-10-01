/*
 * <tested_file_path>src/ocf_freelist.c</tested_file_path>
 * <tested_function>ocf_freelist_populate</tested_function>
 * <functions_to_leave>
 * 	ocf_freelist_init
 * 	ocf_freelist_deinit
 * 	ocf_freelist_populate
 * 	next_phys_invalid
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
#include "metadata/metadata.h"

#include "ocf_freelist.c/ocf_freelist_populate_generated_wraps.c"

ocf_cache_line_t __wrap_ocf_metadata_collision_table_entries(ocf_cache_t cache)
{
	return mock();
}

ocf_cache_line_t __wrap_env_get_execution_context_count(ocf_cache_t cache)
{
	return mock();
}

/* simulate no striping */
ocf_cache_line_t __wrap_ocf_metadata_map_phy2lg(ocf_cache_t cache, ocf_cache_line_t phy)
{
	return phy;
}

bool __wrap_metadata_test_valid_any(ocf_cache_t cache, ocf_cache_line_t cline)
{
	return mock();
}

void __wrap_ocf_metadata_set_partition_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t part_id,
		ocf_cache_line_t next_line, ocf_cache_line_t prev_line)
{
	print_message("%s %u %u %u\n", __func__, prev_line, line, next_line);
	check_expected(line);
	check_expected(part_id);
	check_expected(next_line);
	check_expected(prev_line);
}

#define expect_set_info(curr, part, next, prev) \
	expect_value(__wrap_ocf_metadata_set_partition_info, line, curr); \
	expect_value(__wrap_ocf_metadata_set_partition_info, part_id, part); \
	expect_value(__wrap_ocf_metadata_set_partition_info, next_line, next); \
	expect_value(__wrap_ocf_metadata_set_partition_info, prev_line, prev);

static void ocf_freelist_populate_test01(void **state)
{
	unsigned num_cls = 8;
	unsigned num_ctxts = 3;
	ocf_freelist_t freelist;
	unsigned ctx_iter, cl_iter;

	print_test_description("Verify proper set_partition_info order and arguments - empty cache");

	will_return_maybe(__wrap_ocf_metadata_collision_table_entries, num_cls);
	will_return_maybe(__wrap_env_get_execution_context_count, num_ctxts);
	will_return_maybe(__wrap_metadata_test_valid_any, false);

	freelist = ocf_freelist_init(NULL);

	expect_set_info(0, PARTITION_INVALID, 1      , num_cls);
	expect_set_info(1, PARTITION_INVALID, 2      , 0);
	expect_set_info(2, PARTITION_INVALID, num_cls, 1);
	expect_set_info(3, PARTITION_INVALID, 4      , num_cls);
	expect_set_info(4, PARTITION_INVALID, 5      , 3);
	expect_set_info(5, PARTITION_INVALID, num_cls, 4);
	expect_set_info(6, PARTITION_INVALID, 7      , num_cls);
	expect_set_info(7, PARTITION_INVALID, num_cls, 6);

	ocf_freelist_populate(freelist, num_cls);

	ocf_freelist_deinit(freelist);
}

static void ocf_freelist_populate_test02(void **state)
{
	unsigned num_cls = 8;
	unsigned num_ctxts = 3;
	ocf_freelist_t freelist;
	unsigned ctx_iter, cl_iter;

	print_test_description("Verify proper set_partition_info order and arguments - some valid clines");

	will_return_maybe(__wrap_ocf_metadata_collision_table_entries, num_cls);
	will_return_maybe(__wrap_env_get_execution_context_count, num_ctxts);

	freelist = ocf_freelist_init(NULL);

	/* simulate only cachelines 2, 3, 4, 7 invalid */
	will_return(__wrap_metadata_test_valid_any, true);
	will_return(__wrap_metadata_test_valid_any, true);
	will_return(__wrap_metadata_test_valid_any, false);
	will_return(__wrap_metadata_test_valid_any, false);
	will_return(__wrap_metadata_test_valid_any, false);
	will_return(__wrap_metadata_test_valid_any, true);
	will_return(__wrap_metadata_test_valid_any, true);
	will_return(__wrap_metadata_test_valid_any, false);

	expect_set_info(2, PARTITION_INVALID, 3      , num_cls);
	expect_set_info(3, PARTITION_INVALID, num_cls, 2);
	expect_set_info(4, PARTITION_INVALID, num_cls, num_cls);
	expect_set_info(7, PARTITION_INVALID, num_cls, num_cls);

	ocf_freelist_populate(freelist, 4);

	ocf_freelist_deinit(freelist);
}
int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_freelist_populate_test01),
		cmocka_unit_test(ocf_freelist_populate_test02)
	};

	print_message("Unit test of src/ocf_freelist.c\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
