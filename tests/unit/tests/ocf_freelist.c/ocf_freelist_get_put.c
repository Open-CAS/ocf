/*
 * <tested_file_path>src/ocf_freelist.c</tested_file_path>
 * <tested_function>ocf_freelist_get_cache_line</tested_function>
 * <functions_to_leave>
 *	ocf_freelist_init
 *	ocf_freelist_deinit
 *	ocf_freelist_populate
 *	next_phys_invalid
 *	ocf_freelist_lock
 *	ocf_freelist_trylock
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

static void ocf_freelist_get_cache_line_get_fast(void **state)
{
	unsigned num_cls = 8;
	unsigned num_ctxts = 3;
	ocf_freelist_t freelist;
	unsigned ctx_iter, cl_iter;
	ocf_cache_line_t line;

	print_test_description("Verify get free cache line get fast path");

	will_return_maybe(__wrap_ocf_metadata_collision_table_entries, num_cls);
	will_return_maybe(__wrap_env_get_execution_context_count, num_ctxts);
	will_return_maybe(__wrap_metadata_test_valid_any, false);

	freelist = ocf_freelist_init(NULL);

	ocf_freelist_populate(freelist, num_cls);

	/* now there are following cachelines on per-context lists:
	 * ctx 0: 0, 1, 2
	 * ctx 1: 3, 4, 5
	 * ctx 2: 6, 7
	 */

	/* get cline from context 1 */
	will_return(__wrap_env_get_execution_context, 1);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 3);

	 /* ctx 0: 0, 1, 2
	  * ctx 1: _, 4, 5
	  * ctx 2: 6, 7 */

	/* get cline from context 2 */
	will_return(__wrap_env_get_execution_context, 2);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 6);

	 /* ctx 0: 0, 1, 2
	  * ctx 1: _, 4, 5
	  * ctx 2: _, 7 */

	/* get cline from context 1 */
	will_return(__wrap_env_get_execution_context, 1);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 4);

	 /* ctx 0: 0, 1, 2
	  * ctx 1: _, _, 5
	  * ctx 2: _, 7 */

	/* get cline from context 0 */
	will_return(__wrap_env_get_execution_context, 0);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 0);

	 /* ctx 0: _, 1, 2
	  * ctx 1: _, _, 5
	  * ctx 2: _, 7 */

	/* get cline from context 0 */
	will_return(__wrap_env_get_execution_context, 0);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 1);

	 /* ctx 0: _, _, 2
	  * ctx 1: _, _, 5
	  * ctx 2: _, 7 */

	/* get cline from context 0 */
	will_return(__wrap_env_get_execution_context, 0);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 2);

	 /* ctx 0: _, _, _,
	  * ctx 1: _, _, 5
	  * ctx 2: _, 7 */

	/* get cline from context 2 */
	will_return(__wrap_env_get_execution_context, 2);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 7);

	 /* ctx 0: _, _, _,
	  * ctx 1: _, _, _5
	  * ctx 2: _, _ */

	/* get cline from context 1 */
	will_return(__wrap_env_get_execution_context, 1);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 5);

	 /* ctx 0: _, _, _,
	  * ctx 1: _, _, _
	  * ctx 2: _, _ */

	ocf_freelist_deinit(freelist);
}

static void ocf_freelist_get_cache_line_get_slow(void **state)
{
	unsigned num_cls = 8;
	unsigned num_ctxts = 3;
	ocf_freelist_t freelist;
	unsigned ctx_iter, cl_iter;
	ocf_cache_line_t line;

	print_test_description("Verify get free cache line get slow path");

	will_return_maybe(__wrap_ocf_metadata_collision_table_entries, num_cls);
	will_return_maybe(__wrap_env_get_execution_context_count, num_ctxts);
	will_return_maybe(__wrap_metadata_test_valid_any, false);

	/* always return exec ctx 0 */
	will_return_maybe(__wrap_env_get_execution_context, 0);

	freelist = ocf_freelist_init(NULL);

	ocf_freelist_populate(freelist, num_cls);

	/* now there are following cachelines on per-context lists:
	 * ctx 0: 0, 1, 2
	 * ctx 1: 3, 4, 5
	 * ctx 2: 6, 7
	 */

	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 0);

	 /* ctx 0: _, 1, 2
	  * ctx 1: 3, 4, 5
	  * ctx 2: 6, 7 */

	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 1);

	 /* ctx 0: _, _, 2
	  * ctx 1: 3, 4, 5
	  * ctx 2: 6, 7 */

	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 2);

	 /* ctx 0: _, _, _
	  * ctx 1: 3, 4, 5
	  * ctx 2: 6, 7 */

	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 3);

	 /* ctx 0: _, _, _
	  * ctx 1: _, 4, 5
	  * ctx 2: 6, 7 */

	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 6);

	 /* ctx 0: _, _, _
	  * ctx 1: _, 4, 5
	  * ctx 2: _, 7 */


	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 4);

	/* ctx 0: _, _, _
	 * ctx 1: _, _, 5
	 * ctx 2: _, 7 */

	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 7);

	/* ctx 0: _, _, _
	 * ctx 1: _, _, 5
	 * ctx 2: _, _ */

	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 5);

	 /* ctx 0: _, _, _,
	  * ctx 1: _, _, _
	  * ctx 2: _, _ */

	ocf_freelist_deinit(freelist);
}

static void ocf_freelist_get_cache_line_put(void **state)
{
	unsigned num_cls = 8;
	unsigned num_ctxts = 3;
	ocf_freelist_t freelist;
	unsigned ctx_iter, cl_iter;
	ocf_cache_line_t line;

	print_test_description("Verify freelist cacheline put");

	will_return_maybe(__wrap_ocf_metadata_collision_table_entries, num_cls);
	will_return_maybe(__wrap_env_get_execution_context_count, num_ctxts);
	will_return_maybe(__wrap_metadata_test_valid_any, false);

	freelist = ocf_freelist_init(NULL);

	ocf_freelist_populate(freelist, num_cls);

	/* get some clines from the freelists */
	will_return(__wrap_env_get_execution_context, 0);
	ocf_freelist_get_cache_line(freelist, &line);
	will_return(__wrap_env_get_execution_context, 0);
	ocf_freelist_get_cache_line(freelist, &line);
	will_return(__wrap_env_get_execution_context, 0);
	ocf_freelist_get_cache_line(freelist, &line);
	will_return(__wrap_env_get_execution_context, 0);
	ocf_freelist_get_cache_line(freelist, &line);
	will_return(__wrap_env_get_execution_context, 0);
	ocf_freelist_get_cache_line(freelist, &line);

	 /* ctx 0:
	  * ctx 1: 4, 5
	  * ctx 2: 7 */

	will_return(__wrap_env_get_execution_context, 1);
	ocf_freelist_put_cache_line(freelist, 0);

	will_return(__wrap_env_get_execution_context, 1);
	ocf_freelist_put_cache_line(freelist, 2);

	will_return(__wrap_env_get_execution_context, 2);
	ocf_freelist_put_cache_line(freelist, 3);

	 /* ctx 0:
	  * ctx 1: 4, 5, 0, 2
	  * ctx 2: 7, 3*/

	will_return(__wrap_env_get_execution_context, 1);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 4);

	will_return(__wrap_env_get_execution_context, 1);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 5);

	will_return(__wrap_env_get_execution_context, 1);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 0);

	will_return(__wrap_env_get_execution_context, 1);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 2);

	will_return(__wrap_env_get_execution_context, 2);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 7);

	will_return(__wrap_env_get_execution_context, 2);
	assert(ocf_freelist_get_cache_line(freelist, &line));
	assert_int_equal(line, 3);

	ocf_freelist_deinit(freelist);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_freelist_get_cache_line_get_fast),
		cmocka_unit_test(ocf_freelist_get_cache_line_get_slow),
		cmocka_unit_test(ocf_freelist_get_cache_line_put)
	};

	print_message("Unit test for ocf_freelist_get_cache_line\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
