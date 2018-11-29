/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

//<tested_file_path>src/metadata/metadata_io.c</tested_file_path>
//<tested_function>metadata_io</tested_function>

#undef static
#undef inline

/*
 * This headers must be in test source file. It's important that cmocka.h is
 * last.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "print_desc.h"

/*
 * Headers from tested target.
 */
#include "metadata.h"
#include "metadata_io.h"
#include "../engine/cache_engine.h"
#include "../engine/engine_common.h"
#include "../engine/engine_bf.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_io.h"
#include "../utils/utils_allocator.h"
#include "../ocf_def_priv.h"

uint32_t __wrap_metadata_io_max_page(struct ocf_cache *cache)
{
	function_called();
	return mock();
}

void __wrap_env_cond_resched(void)
{
}

void __wrap_ocf_engine_push_rq_front(struct ocf_request *rq)
{
}

int __wrap_ocf_realloc(void **mem, size_t size, size_t count, size_t *limit)
{
}

int __wrap_ocf_realloc_cp(void **mem, size_t size, size_t count, size_t *limit)
{
}

ocf_ctx_t __wrap_ocf_cache_get_ctx(ocf_cache_t cache)
{
}

int __wrap_ocf_log_raw(const struct ocf_logger *logger, ocf_logger_lvl_t lvl,
		                const char *fmt, ...)
{
}

int __wrap_metadata_submit_io(
                struct ocf_cache *cache,
                struct metadata_io *mio,
                uint32_t count,
                uint32_t written)
{
}

int __wrap_ocf_restart_meta_io(struct ocf_request *req)
{
}

static void metadata_io_test01(void **state)
{
        int result;
        struct metadata_io mio;
        struct ocf_cache cache;

        print_test_description("Check error no. when invalid operation is given");

        mio.dir = -1;
        mio.cache = &cache;

        expect_function_call(__wrap_metadata_io_max_page);
        will_return(__wrap_metadata_io_max_page, 256);

        result = metadata_io(&mio);

        assert_int_equal(result, -EINVAL);
}


int main(void)
{
        const struct CMUnitTest tests[] = {
                cmocka_unit_test(metadata_io_test01)
        };

        return cmocka_run_group_tests(tests, NULL, NULL);
}
