/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

/*
 * This headers must be in test source file. It's important that cmocka.h is
 * last.
 */

#undef static
#undef inline

//<tested_file_path>src/cleaning/cleaning.c</tested_file_path>
//<tested_function>ocf_cleaner_run</tested_function>
//<functions_to_leave>
//ocf_cleaner_set_cmpl
//</functions_to_leave>


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "print_desc.h"

/*
 * Headers from tested target.
 */
#include "cleaning.h"
#include "alru.h"
#include "acp.h"
#include "../ocf_cache_priv.h"
#include "../ocf_ctx_priv.h"
#include "../mngt/ocf_mngt_common.h"
#include "../metadata/metadata.h"

/*
 * Mocked functions. Here we must deliver functions definitions which are not
 * in tested source file.
 */

void __wrap_cleaning_policy_alru_setup(struct ocf_cache *cache)
{}

int __wrap_cleaning_policy_alru_set_cleaning_param(struct ocf_cache *cache,
		uint32_t param_id, uint32_t param_value)
{
}

int __wrap_cleaning_policy_alru_get_cleaning_param(struct ocf_cache *cache,
		uint32_t param_id, uint32_t *param_value)
{
}

int __wrap_cleaning_policy_acp_initialize(struct ocf_cache *cache,
		                int init_metadata, int init_params){}

void __wrap_cleaning_policy_acp_deinitialize(struct ocf_cache *cache){}

int __wrap_cleaning_policy_acp_perform_cleaning(struct ocf_cache *cache,
		                uint32_t io_queue){}

void __wrap_cleaning_policy_acp_init_cache_block(struct ocf_cache *cache,
		                uint32_t cache_line){}

void __wrap_cleaning_policy_acp_set_hot_cache_line(struct ocf_cache *cache,
		                uint32_t cache_line){}

void __wrap_cleaning_policy_acp_purge_block(struct ocf_cache *cache,
		                uint32_t cache_line){}

int __wrap_cleaning_policy_acp_purge_range(struct ocf_cache *cache,
		                int core_id, uint64_t start_byte, uint64_t end_byte){}

int __wrap_cleaning_policy_acp_add_core(ocf_cache_t cache, ocf_core_id_t core_id){}

int __wrap_cleaning_policy_acp_remove_core(ocf_cache_t cache,
		                ocf_core_id_t core_id){}

void __wrap_cleaning_policy_acp_request_pending(struct ocf_request *req){
}

void cleaning_policy_acp_setup(struct ocf_cache *cache)
{
}

int cleaning_policy_acp_set_cleaning_param(struct ocf_cache *cache,
		uint32_t param_id, uint32_t param_value)
{
}

int cleaning_policy_acp_get_cleaning_param(struct ocf_cache *cache,
		uint32_t param_id, uint32_t *param_value)
{
}

int __wrap_cleaning_policy_acp_set_cleaning_parameters(
		struct ocf_cache *cache, struct ocf_cleaning_params *params)
{
}

void __wrap_cleaning_policy_acp_get_cleaning_parameters(
		struct ocf_cache *cache, struct ocf_cleaning_params *params)
{
}

void __wrap_cleaning_policy_alru_init_cache_block(struct ocf_cache *cache,
		                 uint32_t cache_line)
{

}

void __wrap_cleaning_policy_alru_purge_cache_block(struct ocf_cache *cache,
		                 uint32_t cache_line)
{

}

int __wrap_cleaning_policy_alru_purge_range(struct ocf_cache *cache,
		                 int partition_id, int core_id, uint64_t start_byte,
				                                  uint64_t end_byte)
{

}

void __wrap_cleaning_policy_alru_set_hot_cache_line(struct ocf_cache *cache,
		                 uint32_t cache_line)
{

}

int __wrap_cleaning_policy_alru_initialize(struct ocf_cache *cache, int partition_id,
		                 int init_metadata)
{

}

void __wrap_cleaning_policy_alru_deinitialize(ocf_cache_t cache)
{

}

int __wrap_cleaning_policy_alru_flush_block(struct ocf_cache *cache,
		                 uint32_t io_queue, uint32_t count, uint32_t *cache_lines,
				                                  int partition_id, int core_id, uint8_t do_lock)
{

}

int __wrap_cleaning_policy_alru_set_cleaning_parameters(ocf_cache_t cache,
		                 ocf_part_id_t part_id, struct ocf_cleaning_params *params)
{

}

void __wrap_cleaning_policy_alru_get_cleaning_parameters(ocf_cache_t cache,
		                 ocf_part_id_t part_id, struct ocf_cleaning_params *params)
{

}

void __wrap_ocf_queue_get(ocf_queue_t queue)
{

}

int __wrap_cleaning_alru_perform_cleaning(struct ocf_cache *cache, ocf_cleaner_end_t cmpl)
{
	function_called();
	return mock();
}


ocf_cache_t __wrap_ocf_cleaner_get_cache(ocf_cleaner_t c)
{
	function_called();
	return mock_ptr_type(struct ocf_cache*);
}

bool __wrap_ocf_mngt_is_cache_locked(ocf_cache_t cache)
{
	function_called();
	return mock();
}


int __wrap__ocf_cleaner_run_check_dirty_inactive(struct ocf_cache *cache)
{
	function_called();
	return mock();
}

void __wrap_ocf_cleaner_run_complete(ocf_cleaner_t cleaner, uint32_t interval)
{
	function_called();
}

int __wrap_env_bit_test(int nr, const void *addr)
{
	function_called();
	return mock();
}

int __wrap_env_rwsem_down_write_trylock(env_rwsem *s)
{
	function_called();
	return mock();
}

void __wrap_env_rwsem_up_write(env_rwsem *s)
{
	function_called();
}

static void cleaner_complete(ocf_cleaner_t cleaner, uint32_t interval)
{
	function_called();
}

/*
 * Tests of functions. Every test name must be written to tests array in main().
 * Declarations always look the same: static void test_name(void **state);
 */

static void ocf_cleaner_run_test01(void **state)
{
	struct ocf_cache cache;
	ocf_part_id_t part_id;
	uint32_t io_queue;
	int result;

	//Initialize needed structures.
	cache.conf_meta = test_malloc(sizeof(struct ocf_superblock_config));
	cache.conf_meta->cleaning_policy_type = ocf_cleaning_alru;

	print_test_description("Parts are ready for cleaning - should perform cleaning"
			" for each part");

	expect_function_call(__wrap_ocf_cleaner_get_cache);
	will_return(__wrap_ocf_cleaner_get_cache, &cache);

	expect_function_call(__wrap_env_bit_test);
	will_return(__wrap_env_bit_test, 1);

	expect_function_call(__wrap_ocf_mngt_is_cache_locked);
	will_return(__wrap_ocf_mngt_is_cache_locked, 0);

	expect_function_call(__wrap_env_rwsem_down_write_trylock);
	will_return(__wrap_env_rwsem_down_write_trylock, 0);

	expect_function_call(__wrap__ocf_cleaner_run_check_dirty_inactive);
	will_return(__wrap__ocf_cleaner_run_check_dirty_inactive, 0);

	expect_function_call(__wrap_cleaning_alru_perform_cleaning);
	will_return(__wrap_cleaning_alru_perform_cleaning, 0);

	ocf_cleaner_set_cmpl(&cache.cleaner, cleaner_complete);

	ocf_cleaner_run(&cache.cleaner, 0xdeadbeef);

	/* Release allocated memory if allocated with test_* functions */

	test_free(cache.conf_meta);
}

/*
 * Main function. It runs tests.
 */
int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_cleaner_run_test01)
	};

	print_message("Unit test of cleaning.c\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
