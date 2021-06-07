/*
 * <tested_file_path>src/utils/utils_journal.c</tested_file_path>
 * <tested_function>ocf_journal_alloc_space</tested_function>
 * <functions_to_leave>
  ocf_jurnal_clear_op
  ocf_journal_free_space
  is_finished
  mark_finished
  clear_finished
  is_started
  mark_started
  clear_started
  ocf_journal_init
  ocf_journal_deinit
  ocf_journal_start
  ocf_lru_transaction_schema_init
  ocf_journal_schema_init
  ocf_journal_get_op_count
  ocf_journal_capacity
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
#include "ocf_env.h"
#include "utils_journal.h"
#include "../eviction/lru_transaction_schema.h"

#include "utils/utils_journal.c/utils_journal_generated_wraps.c"

void __wrap___assert_fail (const char *__assertion, const char *__file,
      unsigned int __line, const char *__function)
{
       print_message("assertion failure %s in %s:%u %s\n",
               __assertion, __file, __line, __function);
       assert_int_equal(1, 0);
}

void *g_buf;
struct ocf_journal_schema *g_schema;

void test_schema_init()
{
	g_schema = calloc(sizeof(*g_schema), 1);
	assert(g_schema != NULL);
	ocf_journal_schema_init(g_schema);
}

ocf_journal_t test_prepare_journal(size_t size)
{
	ocf_journal_t journal;
	int ret;

	g_buf = calloc(size, 1);
	assert(g_buf != NULL);

	ret = ocf_journal_init(NULL, g_schema, g_buf, size, &journal);

	if (!ret) {
		ocf_journal_start(journal);
		return journal;
	} else {
		free(g_buf);
		return NULL;
	}
}

void test_cleanup_journal(ocf_journal_t journal)
{
	ocf_journal_deinit(journal);
	free(g_buf);
}

static void ocf_journal_init_test01(void **state)
{
	ocf_journal_t journal;

	print_test_description("journal init fail for buff size = 1\n");

	/* buffer to small - 1 B */
	journal = test_prepare_journal(1);
	assert_ptr_equal(NULL, journal);
}

static void ocf_journal_init_test02(void **state)
{
	ocf_journal_t journal;

	print_test_description("journal init fail for buff size = hdr size\n");

	/* buffer to small - only header size */
	journal = test_prepare_journal(sizeof(struct ocf_journal_hdr));
	assert_ptr_equal(NULL, journal);
}

static void ocf_journal_init_test03(void **state)
{
	ocf_journal_t journal;

	print_test_description("journal init sucess for miminal valid size\n");

	/* ring buffer space for 1 op */
	journal = test_prepare_journal(sizeof(struct ocf_journal_hdr) +
			sizeof(struct ocf_journal_op));
	assert_ptr_not_equal(NULL, journal);

	test_cleanup_journal(journal);
}

static void test_mark_finished(ocf_journal_t journal, ocf_journal_idx_t pos,
		ocf_journal_idx_t count)
{
	ocf_journal_idx_t i;
	ocf_journal_idx_t capacity = journal->ring.hdr->capacity;
	struct ocf_journal_op *op;

	for (i = pos; i != (pos + count) %  capacity; i = (i + 1) % capacity) {
		op = &journal->ring.buff[i];
		assert_int_equal(is_finished(op), false);
		mark_finished(op);
		assert_int_equal(is_finished(op), true);
	}
}

static void ocf_journal_alloc_test01(void **state)
{
	ocf_journal_t journal;
	ocf_journal_idx_t pos;
	ocf_journal_idx_t capacity = 10;
	bool ret;
	size_t count = 7;


	print_test_description("7 ops alloc & free 4 times\n");

	journal = test_prepare_journal(sizeof(struct ocf_journal_hdr) +
			capacity * sizeof(struct ocf_journal_op));
	assert_ptr_not_equal(NULL, journal);
	assert_int_equal(journal->ring.hdr->capacity, capacity);

	ret = ocf_journal_alloc_space(journal, count, &pos);
	assert_int_equal(ret, true);
	test_mark_finished(journal, pos, count);
	ocf_journal_free_space(journal, pos);

	ret = ocf_journal_alloc_space(journal, count, &pos);
	test_mark_finished(journal, pos, count);
	assert_int_equal(ret, true);

	ocf_journal_free_space(journal, pos);

	ret = ocf_journal_alloc_space(journal, count, &pos);
	assert_int_equal(ret, true);
	test_mark_finished(journal, pos, count);
	ocf_journal_free_space(journal, pos);

	ret = ocf_journal_alloc_space(journal, count, &pos);
	assert_int_equal(ret, true);
	test_mark_finished(journal, pos, count);
	ocf_journal_free_space(journal, pos);

	test_cleanup_journal(journal);
}

static void ocf_journal_alloc_test02(void **state)
{
	ocf_journal_t journal;
	ocf_journal_idx_t pos;
	ocf_journal_idx_t capacity = 10;
	bool ret;
	int i;
	int repeat_count = 2;

	print_test_description("test buffer overflow\n");

	journal = test_prepare_journal(sizeof(struct ocf_journal_hdr) +
			capacity * sizeof(struct ocf_journal_op));
	assert_ptr_not_equal(NULL, journal);
	assert_int_equal(journal->ring.hdr->capacity, capacity);

	while (repeat_count--) {
		for (i = 0; i < capacity; i++) {
			ret = ocf_journal_alloc_space(journal, 1, &pos);
			assert_int_equal(ret, true);
		}

		ret = ocf_journal_alloc_space(journal, 1, &pos);
		assert_int_equal(ret, false);

		for (i = 0; i < capacity; i++) {
			test_mark_finished(journal, i, 1);
			ocf_journal_free_space(journal, i);
		}
	}

	test_cleanup_journal(journal);
}

static void ocf_journal_alloc_test03(void **state)
{
	ocf_journal_t journal;
	ocf_journal_idx_t capacity = 10;
	bool ret;
	ocf_journal_idx_t alloc_size[] = {1, 7, 1, 2, 8, 1};
	ocf_journal_idx_t alloc_pos[sizeof(alloc_size) / sizeof(alloc_size[0])];

	print_test_description("only finished ops should be freed\n");

	journal = test_prepare_journal(sizeof(struct ocf_journal_hdr) +
			capacity * sizeof(struct ocf_journal_op));

	/* >E<EEEEEEEEE
	 *   < - pointing to started idx
	 *   > - pointing to finished idx
	 *   E - empty
	 *   S - started
	 *   F - finished
	 */

	/* alloc idx 0 - 0 */
	ret = ocf_journal_alloc_space(journal, alloc_size[0], &alloc_pos[0]);
	assert_int_equal(ret, true);

	/* >SE<EEEEEEEE */

	/* alloc idx 1 - 7 */
	ret = ocf_journal_alloc_space(journal, alloc_size[1], &alloc_pos[1]);
	assert_int_equal(ret, true);

	/* >SSSSSSSSE<E */

	/* alloc idx 8-8 */
	ret = ocf_journal_alloc_space(journal, alloc_size[2], &alloc_pos[2]);
	assert_int_equal(ret, true);

	/* >SSSSSSSSSE< */

	/* attempt to alloc 2 - not enough space*/
	ret = ocf_journal_alloc_space(journal, alloc_size[3], &alloc_pos[3]);
	assert_int_equal(ret, false);

	/* >SSSSSSSSSE< */

	/* simulate freeing of idx 1-7 */
	test_mark_finished(journal, alloc_pos[1], alloc_size[1]);
	ocf_journal_free_space(journal, alloc_pos[1]);

	/* >SFFFFFFFSE< */

	/* attempt to alloc 2 - finished idx still not advanced so will fail*/
	ret = ocf_journal_alloc_space(journal, alloc_size[3], &alloc_pos[3]);
	assert_int_equal(ret, false);

	/* >SFFFFFFFSE< */

	/* simulate freeing of idx 0 - 0 */
	test_mark_finished(journal, alloc_pos[0], alloc_size[0]);
	ocf_journal_free_space(journal, alloc_pos[0]);

	/* EEEEEEEE>SE< */

	/* alloc 2 - should succeeed - indexes 0-8 are empty */
	ret = ocf_journal_alloc_space(journal, alloc_size[3], &alloc_pos[3]);
	assert_int_equal(ret, true);

	/* SE<EEEEEE>SS */

	/* alloc 8 - should fail (allocation at 8 still not freed) */
	ret = ocf_journal_alloc_space(journal, alloc_size[4], &alloc_pos[4]);
	assert_int_equal(ret, false);

	/* SE<EEEEEE>SS */

	/* simulate freeing of idx 8-8 */
	test_mark_finished(journal, alloc_pos[2], alloc_size[2]);
	ocf_journal_free_space(journal, alloc_pos[2]);

	/* SE<EEEEEEE>S */

	/* alloc 8 - should succeed */
	ret = ocf_journal_alloc_space(journal, alloc_size[4], &alloc_pos[4]);
	assert_int_equal(ret, true);

	/* attempt to alloc 1 - should fail (buffer full) */
	ret = ocf_journal_alloc_space(journal, alloc_size[5], &alloc_pos[5]);
	assert_int_equal(ret, false);

	test_cleanup_journal(journal);
}
int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_journal_init_test01),
		cmocka_unit_test(ocf_journal_init_test02),
		cmocka_unit_test(ocf_journal_init_test03),
		cmocka_unit_test(ocf_journal_alloc_test01),
		cmocka_unit_test(ocf_journal_alloc_test02),
		cmocka_unit_test(ocf_journal_alloc_test03),
	};

	print_message("Unit test for journal utility\n");

	test_schema_init();

	return cmocka_run_group_tests(tests, NULL, NULL);
}
