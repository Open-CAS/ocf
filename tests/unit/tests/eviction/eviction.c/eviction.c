/*
 * <tested_file_path>src/eviction/eviction.c</tested_file_path>
 * <tested_function>ocf_evict_do</tested_function>
 * <functions_to_leave>
	ocf_evict_partitions
 * </functions_to_leave>
 */

#undef static

#undef inline


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "print_desc.h"

#include "eviction.h"
#include "ops.h"
#include "../utils/utils_part.h"

#include "eviction/eviction.c/eviction_generated_wraps.c"

struct test_cache
{
	struct ocf_cache cache;
	struct ocf_user_part_config part[OCF_IO_CLASS_MAX];
	struct ocf_part_runtime runtime[OCF_IO_CLASS_MAX];
	uint32_t overflow[OCF_IO_CLASS_MAX];
	uint32_t evictable[OCF_IO_CLASS_MAX];
	uint32_t req_unmapped;
};

uint32_t __wrap_ocf_lru_num_free(ocf_cache_t cache)
{
	return 0;
}

bool __wrap_ocf_eviction_can_evict(ocf_cache_t cache)
{
	return true;
}

uint32_t __wrap_ocf_part_overflow_size(struct ocf_cache *cache,
		struct ocf_user_part *part)
{
	struct test_cache* tcache = cache;

	return tcache->overflow[part->id];
}

uint32_t __wrap_ocf_evict_calculate(ocf_cache_t cache,
		struct ocf_user_part *part, uint32_t to_evict, bool roundup)
{
	struct test_cache* tcache = cache;

	return min(tcache->evictable[part->id], to_evict);
}

uint32_t __wrap_ocf_eviction_need_space(struct ocf_cache *cache,
	ocf_queue_t io_queue, struct ocf_part_runtime *part,
	ocf_part_id_t part_id, uint32_t clines)
{
	struct test_cache *tcache = (struct test_cache *)cache;
	unsigned overflown_consumed;

	overflown_consumed = min(clines, tcache->overflow[part_id]);

	tcache->overflow[part_id] -= overflown_consumed;
	tcache->evictable[part_id] -= clines;
	tcache->req_unmapped -= clines;

	check_expected(part);
	check_expected(clines);
	function_called();

	return mock();
}

int __wrap_ocf_log_raw(ocf_logger_t logger, ocf_logger_lvl_t lvl,
		const char *fmt, ...)
{
}

int __wrap_ocf_log_stack_trace_raw(ocf_logger_t logger)
{
	return 0;
}

ocf_ctx_t __wrap_ocf_cache_get_ctx(ocf_cache_t cache)
{
	return NULL;
}


bool ocf_cache_is_device_attached(ocf_cache_t cache)
{
	return true;
}


/* FIXME: copy-pasted from OCF */
int ocf_part_lst_cmp_valid(struct ocf_cache *cache,
		struct ocf_lst_entry *e1, struct ocf_lst_entry *e2)
{
	struct ocf_user_part *p1 = container_of(e1, struct ocf_user_part,
			lst_valid);
	struct ocf_user_part *p2 = container_of(e2, struct ocf_user_part,
			lst_valid);
	size_t p1_size = ocf_cache_is_device_attached(cache) ?
				env_atomic_read(&p1->runtime->curr_size) : 0;
	size_t p2_size = ocf_cache_is_device_attached(cache) ?
				env_atomic_read(&p2->runtime->curr_size) : 0;

	int v1 = p1->config->priority;
	int v2 = p2->config->priority;

	/*
	 * If partition is invalid the priority depends on current size:
	 * 1. Partition is empty - move to the end of list
	 * 2. Partition is not empty  - move to the beginning of the list. This
	 * partition will be evicted first
	 */

	if (p1->config->priority == OCF_IO_CLASS_PRIO_PINNED)
		p1->config->flags.eviction = false;
	else
		p1->config->flags.eviction = true;

	if (p2->config->priority == OCF_IO_CLASS_PRIO_PINNED)
		p2->config->flags.eviction = false;
	else
		p2->config->flags.eviction = true;

	if (!p1->config->flags.valid) {
		if (p1_size) {
			v1 = SHRT_MAX;
			p1->config->flags.eviction = true;
		} else {
			v1 = SHRT_MIN;
			p1->config->flags.eviction = false;
		}
	}

	if (!p2->config->flags.valid) {
		if (p2_size) {
			v2 = SHRT_MAX;
			p2->config->flags.eviction = true;
		} else {
			v2 = SHRT_MIN;
			p2->config->flags.eviction = false;
		}
	}

	if (v1 == v2) {
		v1 = p1 - cache->user_parts;
		v2 = p2 - cache->user_parts;
	}

	return v2 - v1;
}

static struct ocf_lst_entry *_list_getter(
		struct ocf_cache *cache, ocf_cache_line_t idx)
{
	struct test_cache* tcache = cache;

	return &tcache->cache.user_parts[idx].lst_valid;
}

static void init_part_list(struct test_cache *tcache)
{
	unsigned i;

	for (i = 0; i < OCF_IO_CLASS_MAX; i++) {
		tcache->cache.user_parts[i].id = i;
		tcache->cache.user_parts[i].config = &tcache->part[i];
		tcache->cache.user_parts[i].runtime = &tcache->runtime[i];
		tcache->cache.user_parts[i].config->priority = i+1;
		tcache->cache.user_parts[i].config->flags.eviction = 1;
	}

	ocf_lst_init((ocf_cache_t)tcache, &tcache->cache.lst_part, OCF_IO_CLASS_MAX,
			_list_getter, ocf_part_lst_cmp_valid);
	for (i = 0; i < OCF_IO_CLASS_MAX; i++) {
		ocf_lst_init_entry(&tcache->cache.lst_part, &tcache->cache.user_parts[i].lst_valid);
		ocf_lst_add_tail(&tcache->cache.lst_part, i);
	}
}

uint32_t __wrap_ocf_engine_unmapped_count(struct ocf_request *req)
{
	struct test_cache* tcache = (struct test_cache*)req->cache;

	return tcache->req_unmapped;
}

#define _expect_evict_call(tcache, part_id, req_count, ret_count) \
	do { \
		expect_value(__wrap_ocf_eviction_need_space, part, tcache.cache.user_parts[part_id].runtime); \
		expect_value(__wrap_ocf_eviction_need_space, clines, req_count); \
		expect_function_call(__wrap_ocf_eviction_need_space); \
		will_return(__wrap_ocf_eviction_need_space, ret_count); \
	} while (false);

static void ocf_evict_do_test01(void **state)
{
	struct test_cache tcache = {};
	struct ocf_request req = {.cache = &tcache.cache, .part_id = 0 };
	unsigned evicted;

	print_test_description("one IO class, no overflow\n");

	init_part_list(&tcache);

	tcache.evictable[10] = 100;
	tcache.req_unmapped = 50;

	_expect_evict_call(tcache, 10, 50, 50);
	evicted = ocf_evict_do(&req);
	assert_int_equal(evicted, 50);
}

static void ocf_evict_do_test02(void **state)
{
	struct test_cache tcache = {};
	struct ocf_request req = {.cache = &tcache.cache, .part_id = 0 };
	unsigned i;
	unsigned evicted;

	print_test_description("one overflown IO class\n");

	init_part_list(&tcache);

	tcache.evictable[10] = 100;
	tcache.overflow[10] = 100;
	tcache.req_unmapped = 50;

	_expect_evict_call(tcache, 10, 50, 50);

	evicted = ocf_evict_do(&req);
	assert_int_equal(evicted, 50);
}

static void ocf_evict_do_test03(void **state)
{
	struct test_cache tcache = {};
	struct ocf_request req = {.cache = &tcache.cache, .part_id = 0 };
	unsigned i;
	unsigned evicted;

	print_test_description("multiple non-overflown IO class\n");

	init_part_list(&tcache);

	tcache.evictable[10] = 100;
	tcache.evictable[12] = 100;
	tcache.evictable[16] = 100;
	tcache.evictable[17] = 100;
	tcache.req_unmapped = 350;

	_expect_evict_call(tcache, 10, 100, 100);
	_expect_evict_call(tcache, 12, 100, 100);
	_expect_evict_call(tcache, 16, 100, 100);
	_expect_evict_call(tcache, 17, 50, 50);

	evicted = ocf_evict_do(&req);
	assert_int_equal(evicted, 350);
}

static void ocf_evict_do_test04(void **state)
{
	struct test_cache tcache = {};
	struct ocf_request req = {.cache = &tcache.cache, .part_id = 0 };
	unsigned i;
	unsigned evicted;

	print_test_description("multiple IO class with and without overflow\n");

	init_part_list(&tcache);

	tcache.evictable[10] = 100;
	tcache.evictable[12] = 100;
	tcache.overflow[12] = 40;
	tcache.evictable[14] = 100;
	tcache.overflow[14] = 100;
	tcache.evictable[16] = 100;
	tcache.evictable[17] = 100;
	tcache.evictable[18] = 100;
	tcache.overflow[18] = 100;
	tcache.req_unmapped = 580;

	_expect_evict_call(tcache, 12, 40, 40);
	_expect_evict_call(tcache, 14, 100, 100);
	_expect_evict_call(tcache, 18, 100, 100);
	_expect_evict_call(tcache, 10, 100, 100);
	_expect_evict_call(tcache, 12, 60, 60);
	_expect_evict_call(tcache, 16, 100, 100);
	_expect_evict_call(tcache, 17, 80, 80);

	evicted = ocf_evict_do(&req);
	assert_int_equal(evicted, 580);
}
int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_evict_do_test01),
		cmocka_unit_test(ocf_evict_do_test02),
		cmocka_unit_test(ocf_evict_do_test03),
		cmocka_unit_test(ocf_evict_do_test04)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
