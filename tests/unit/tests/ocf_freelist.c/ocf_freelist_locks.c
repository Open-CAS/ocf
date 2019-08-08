/*
 * <tested_file_path>src/ocf_freelist.c</tested_file_path>
 * <tested_function>ocf_freelist_get_cache_line</tested_function>
 * <functions_to_leave>
 *	ocf_freelist_init
 *	ocf_freelist_deinit
 *	ocf_freelist_populate
 *	next_phys_invalid
 *	ocf_freelist_unlock
 *	_ocf_freelist_remove_cache_line
 *	ocf_freelist_get_cache_line_fast
 *	ocf_freelist_get_cache_line_slow
 *	ocf_freelist_add_cache_line
 *	ocf_freelist_get_cache_line_ctx
 *	get_next_victim_freelist
 *	ocf_freelist_put_cache_line
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

#include "ocf_freelist.c/ocf_freelist_get_put_generated_wraps.c"

ocf_cache_line_t __wrap_ocf_metadata_collision_table_entries(ocf_cache_t cache)
{
	return mock();
}

unsigned  __wrap_env_get_execution_context_count(void)
{
	return mock();
}

unsigned __wrap_env_get_execution_context(void)
{
	return mock();
}

void __wrap_env_put_execution_context(unsigned ctx)
{
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

void __wrap_ocf_freelist_lock(ocf_freelist_t freelist, uint32_t ctx)
{
	function_called();
	check_expected(ctx);
}

int __wrap_ocf_freelist_trylock(ocf_freelist_t freelist, uint32_t ctx)
{
	function_called();
	check_expected(ctx);
	return mock();
}

/* metadata partition info interface mock: */

#define max_clines  100

struct {
	ocf_cache_line_t prev;
	ocf_cache_line_t next;
} partition_list[max_clines];


void __wrap_ocf_metadata_set_partition_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t part_id,
		ocf_cache_line_t next_line, ocf_cache_line_t prev_line)
{
	assert_int_equal(part_id, PARTITION_INVALID);
	partition_list[line].prev = prev_line;
	partition_list[line].next = next_line;
}

void __wrap_ocf_metadata_get_partition_info(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t *part_id,
		ocf_cache_line_t *next_line, ocf_cache_line_t *prev_line)
{
	if (part_id)
		*part_id = PARTITION_INVALID;
	if (prev_line)
		*prev_line = partition_list[line].prev;
	if (next_line)
		*next_line = partition_list[line].next;
}

void __wrap_ocf_metadata_set_partition_prev(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_cache_line_t prev_line)
{
	partition_list[line].prev = prev_line;
}

void __wrap_ocf_metadata_set_partition_next(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_cache_line_t next_line)
{
	partition_list[line].next = next_line;
}

static void ocf_freelist_get_put_locks(void **state)
{
	unsigned num_cls = 4;
	unsigned num_ctxts = 3;
	ocf_freelist_t freelist;
	unsigned ctx_iter, cl_iter;
	ocf_cache_line_t line;

	print_test_description("Verify lock/trylock sequence in get free cacheline");

	will_return_maybe(__wrap_ocf_metadata_collision_table_entries, num_cls);
	will_return_maybe(__wrap_env_get_execution_context_count, num_ctxts);
	will_return_maybe(__wrap_metadata_test_valid_any, false);

	/* simulate context 1 for the entire test duration */
	will_return_maybe(__wrap_env_get_execution_context, 1);

	freelist = ocf_freelist_init(NULL);

	ocf_freelist_populate(freelist, num_cls);

	/****************************************************************/
	/* verify fast path locking - scucessfull trylock */

	/* ctx 0: 0, 3
	 * ctx 1: 1
	 * ctx 2: 2
	 * slowpath next victim: 0
	 */

	expect_value(__wrap_ocf_freelist_trylock, ctx, 1);
	expect_function_call(__wrap_ocf_freelist_trylock);
	will_return(__wrap_ocf_freelist_trylock, 0);
	ocf_freelist_get_cache_line(freelist, &line);

	/****************************************************************/
	/* verify fast path locking - scucessfull trylock in slowpath */

	/* ctx 0: 0, 3
	 * ctx 1:
	 * ctx 2: 2
	 * slowpath next victim: 0 */

	/* we expect trylock for context 0, since context 1 has empty list */
	expect_value(__wrap_ocf_freelist_trylock, ctx, 0);
	expect_function_call(__wrap_ocf_freelist_trylock);
	will_return(__wrap_ocf_freelist_trylock, 0);
	ocf_freelist_get_cache_line(freelist, &line);

	/****************************************************************/
	/* verify fast path locking - trylock failure in slowpath */

	/* ctx 0: 3
	 * ctx 1:
	 * ctx 2: 2
	 * slowpath next victim: 1 */

	/* fastpath will fail immediately - context 1 list is empty */
	/* next slowpath victim context (1) is empty - will move to ctx 2 */
	/* so now we expect trylock for context no 2 - injecting error here*/
	expect_value(__wrap_ocf_freelist_trylock, ctx, 2);
	expect_function_call(__wrap_ocf_freelist_trylock);
	will_return(__wrap_ocf_freelist_trylock, 1);

	/* slowpath will attempt to trylock next non-empty context - 0
	 * - injecting error here as well */
	expect_value(__wrap_ocf_freelist_trylock, ctx, 0);
	expect_function_call(__wrap_ocf_freelist_trylock);
	will_return(__wrap_ocf_freelist_trylock, 1);

	/* slowpath trylock loop failed - expecting full lock */
	expect_value(__wrap_ocf_freelist_lock, ctx, 2);
	expect_function_call(__wrap_ocf_freelist_lock);

	/* execute freelist_get_cache_line */
	ocf_freelist_get_cache_line(freelist, &line);

	/****************************************************************/

	ocf_freelist_deinit(freelist);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_freelist_get_put_locks)
	};

	print_message("Unit test for ocf_freelist_get_cache_line locking\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
