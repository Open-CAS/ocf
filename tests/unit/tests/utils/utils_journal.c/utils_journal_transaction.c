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
  ocf_journal_start_op
  ocf_journal_finish_op
  ocf_journal_finish_transaction
  ocf_journal_start_transaction
  ocf_journal_start_debug_check
  ocf_journal_get_next
  get_op_by_idx
  ocf_journal_schema_dfs
  _ocf_journal_schema_dfs
  ocf_journal_start_debug_cb
  ocf_journal_finish_debug_check
  ocf_journal_finish_debug_cb
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

void simulate_op(ocf_journal_t journal, struct ocf_journal_op *op)
{
	struct ocf_journal_op *master_op = op;
	enum ocf_journal_op_id op_id;
	unsigned i;

	assert_int_equal(is_started(op), true);
	assert_int_equal(is_finished(op), false);

	for (i = 0; i < journal->schema->sub_op_count[master_op->id]; i++) {
		op_id = journal->schema->sub_ops[master_op->id][i];
		OCF_JOURNAL_START(op_id);
		assert_int_equal(op->id, op_id);
		simulate_op(journal, op);
		OCF_JOURNAL_END();
		assert_ptr_equal(op, master_op);
	}

	assert_int_equal(is_started(op), true);
	assert_int_equal(is_finished(op), false);
}

static void ocf_journal_transaction_test(void **state)
{
	enum ocf_journal_op_id op_id = ocf_journal_op_id_lru_repart;
	size_t transaction_op_count = ocf_journal_get_op_count(g_schema, op_id);
	ocf_journal_t journal;
	ocf_journal_idx_t capacity = 2 * transaction_op_count  - 1;
	ocf_journal_idx_t pos, curr_pos;
	bool ret;
	unsigned i;
	unsigned iter_count = 3, iter;


	print_test_description("verify that all sub-ops are visited using START/END macros\n");

	/* test with different transaction start offset within the buffer */
	for (i = 0; i + 1 < transaction_op_count; i++) {
		journal = test_prepare_journal(sizeof(struct ocf_journal_hdr) +
			capacity * sizeof(struct ocf_journal_op));

		/* move to offset i in the ring buffer */
		if (i > 0) {
			ret = ocf_journal_alloc_space(journal, i, &pos);
			assert_int_equal(ret, true);
		}

		/* simulate entire transaction 'iter_count' times */
		for (iter = 0; iter < iter_count; iter++) {
			struct ocf_journal_op *op = OCF_JOURNAL_OP_INIT_VAL();

			OCF_JOURNAL_TRANSACTION_START(journal, op_id);
			assert_int_equal(op->id, op_id);

			if (iter == 0 && i > 0) {
				/* simulate freeing initial allocation */
				test_mark_finished(journal, 0, i);
				 ocf_journal_free_space(journal, 0);
			}

			for (curr_pos = op->ring_idx;
					curr_pos != (op->ring_idx + transaction_op_count) % capacity;
					curr_pos = (curr_pos + 1) % capacity) {
				assert_int_equal(is_started(&journal->ring.buff[curr_pos]), false);
				assert_int_equal(is_finished(&journal->ring.buff[curr_pos]), false);
			}

			OCF_JOURNAL_START(op_id);
			simulate_op(journal, op);
			OCF_JOURNAL_END();

			for (curr_pos = op->ring_idx;
					curr_pos != (op->ring_idx + transaction_op_count) % capacity;
					curr_pos = (curr_pos + 1) % capacity) {
				assert_int_equal(is_started(&journal->ring.buff[curr_pos]), true);
				assert_int_equal(is_finished(&journal->ring.buff[curr_pos]), true);
			}

			OCF_JOURNAL_TRANSACTION_END(journal);
		}

		assert_int_equal(journal->ring.hdr->started_idx, journal->ring.hdr->finished_idx);
		assert_int_equal(journal->ring.hdr->full, false);

		test_cleanup_journal(journal);
	}
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_journal_transaction_test),
	};

	print_message("Unit test for journal utility\n");

	test_schema_init();

	return cmocka_run_group_tests(tests, NULL, NULL);
}
