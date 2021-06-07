#include "../utils/utils_journal.h"

void ocf_lru_rollback_remove_update_ptrs(ocf_cache_t cache, ocf_jop_t op);
void ocf_lru_rollback_remove_dec_count(ocf_cache_t cache, ocf_jop_t op);
void ocf_lru_rollback_remove_clear_elem(ocf_cache_t cache, ocf_jop_t op);
void ocf_lru_rollback_balance_update_ctr(ocf_cache_t cache, ocf_jop_t op);
void ocf_lru_rollback_balance_update_last(ocf_cache_t cache, ocf_jop_t op);
void ocf_lru_rollback_balance_set_hot(ocf_cache_t cache, ocf_jop_t op);
void ocf_lru_rollback_move(ocf_cache_t cache, ocf_jop_t op);
void ocf_lru_rollback_insert_lru_head(ocf_cache_t cache, ocf_jop_t op);
void ocf_lru_rollback_set_hot(ocf_cache_t cache, ocf_jop_t op);

static inline void ocf_lru_transaction_schema_init(
		struct ocf_journal_schema *schema)
{
	declare_sub_ops(schema, ocf_journal_op_id_lru_repart,
			ocf_journal_op_id_lru_del,
			ocf_journal_op_id_lru_add,
			ocf_journal_op_set_part);
	declare_sub_ops(schema, ocf_journal_op_id_lru_del,
			ocf_journal_op_id_lru_unlink,
			ocf_journal_op_id_lru_balance);
	declare_sub_ops(schema, ocf_journal_op_id_lru_unlink,
			ocf_journal_op_id_lru_update_ptrs,
			ocf_journal_op_id_lru_dec_count,
			ocf_journal_op_id_lru_clear_elem);

	/* parent op must always use ocf_jdata_lru_list data struct */
	declare_sub_ops(schema, ocf_journal_op_id_lru_balance,
			ocf_journal_op_id_lru_balance_update_ctr,
			ocf_journal_op_id_lru_balance_update_last,
			ocf_journal_op_id_lru_balance_set_hot);
	declare_sub_ops(schema, ocf_journal_op_id_lru_add,
			ocf_journal_op_id_lru_add_insert,
			ocf_journal_op_id_lru_balance);

	declare_sub_ops(schema, ocf_journal_op_id_lru_clean_update,
		ocf_journal_op_id_lru_del,
		ocf_journal_op_id_lru_add);

	declare_sub_ops(schema, ocf_journal_op_id_lru_clean_update,
		ocf_journal_op_id_lru_del,
		ocf_journal_op_id_lru_add);

	declare_sub_ops(schema, ocf_journal_op_id_lru_set_hot,
		ocf_journal_op_id_lru_unlink,
		ocf_journal_op_id_lru_add_insert,
		ocf_journal_op_id_lru_balance);


	declare_rollback_cb(schema, ocf_journal_op_id_lru_update_ptrs,
			ocf_lru_rollback_remove_update_ptrs);
	declare_rollback_cb(schema, ocf_journal_op_id_lru_dec_count,
			ocf_lru_rollback_remove_dec_count);
	declare_rollback_cb(schema, ocf_journal_op_id_lru_clear_elem,
			ocf_lru_rollback_remove_clear_elem);
	declare_rollback_cb(schema, ocf_journal_op_id_lru_balance_update_ctr,
			ocf_lru_rollback_balance_update_ctr);
	declare_rollback_cb(schema, ocf_journal_op_id_lru_balance_update_last,
			ocf_lru_rollback_balance_update_last);
	declare_rollback_cb(schema, ocf_journal_op_id_lru_balance_set_hot,
			ocf_lru_rollback_balance_set_hot);
	declare_rollback_cb(schema, ocf_journal_op_id_lru_add_insert,
			ocf_lru_rollback_insert_lru_head);

	/* composit operations with a dedicated rollback function due to
	 * locking dependencies (sub-ops data potentilaly stale after marking
	 * master op as finished)
	 */
	declare_rollback_cb(schema, ocf_journal_op_id_lru_repart,
			ocf_lru_rollback_move);
	declare_rollback_cb(schema, ocf_journal_op_id_lru_set_hot,
			ocf_lru_rollback_set_hot);


}
