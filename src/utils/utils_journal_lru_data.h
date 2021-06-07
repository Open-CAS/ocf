/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#pragma once

struct ocf_jdata_lru_move {
	ocf_part_id_t src_part;
	ocf_part_id_t dst_part;
	ocf_cache_line_t cline;
	bool clean;
};

struct ocf_jdata_lru_del {
	ocf_cache_line_t cline;
	ocf_part_id_t part;
	bool clean;
};

struct ocf_jdata_lru_unlink {
	ocf_cache_line_t cline;
};

struct ocf_jdata_lru_del_update_pointers {
	ocf_cache_line_t prev;
	ocf_cache_line_t next;
	ocf_cache_line_t curr_last_hot;
};

struct ocf_jdata_lru_del_dec_count {
	unsigned curr_node_count;
	unsigned curr_hot_count;
	bool is_hot;
};

struct ocf_jdata_lru_del_dec_hot {
	unsigned curr_count;
	bool is_hot;
};

struct ocf_jdata_lru_list {
	ocf_cache_line_t cline;
	ocf_part_id_t part_id;
	bool clean;
};

struct ocf_jdata_lru_balance_set_hot {
	ocf_cache_line_t cline;
	bool was_hot;
};

struct ocf_jdata_lru_add_insert {
	ocf_cache_line_t cline;
	ocf_cache_line_t head;
	ocf_cache_line_t num_nodes;
};

