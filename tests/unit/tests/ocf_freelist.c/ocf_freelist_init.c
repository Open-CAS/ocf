/*
 * <tested_file_path>src/ocf_freelist.c</tested_file_path>
 * <tested_function>ocf_freelist_populate</tested_function>
 * <functions_to_leave>
 * 	ocf_freelist_init
 * 	ocf_freelist_deinit
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

#include "ocf_freelist.c/ocf_freelist_init_generated_wraps.c"

ocf_cache_line_t __wrap_ocf_metadata_collision_table_entries(ocf_cache_t cache)
{
	function_called();
	return mock();
}

ocf_cache_line_t __wrap_env_get_execution_context_count(ocf_cache_t cache)
{
	function_called();
	return mock();
}

static void ocf_freelist_init_test01(void **state)
{
	unsigned num_cls = 9;
	unsigned num_ctxts = 3;
	ocf_freelist_t freelist;
	ocf_cache_t cache = 0x1234;

	print_test_description("Freelist initialization test");

	expect_function_call(__wrap_ocf_metadata_collision_table_entries);
	will_return(__wrap_ocf_metadata_collision_table_entries, num_cls);

	expect_function_call(__wrap_env_get_execution_context_count);
	will_return(__wrap_env_get_execution_context_count, num_ctxts);

	freelist = ocf_freelist_init(cache);
	assert(freelist != NULL);

	ocf_freelist_deinit(freelist);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_freelist_init_test01)
	};

	print_message("Unit test of ocf_freelist_init\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
