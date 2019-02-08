/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

//<tested_file_path>src/metadata/metadata_io.c</tested_file_path>
//<tested_function>metadata_submit_io</tested_function>

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
#include "../utils/utils_allocator.h"
#include "../ocf_def_priv.h"

struct ocf_io *__wrap_ocf_new_cache_io(struct ocf_cache *cache)
{
	function_called();
	return mock_ptr_type(struct ocf_io *);
}

int __wrap_metadata_io_write_fill(struct ocf_cache *cache,
		ctx_data_t *data, uint32_t page, void *context)
{
	function_called();
	return mock();
}

void *__wrap_ctx_data_alloc(ocf_ctx_t ctx, uint32_t pages)
{
	function_called();
	return mock_ptr_type(void*);
}

void __wrap_ocf_io_configure(struct ocf_io *io, uint64_t addr,
	uint32_t bytes, uint32_t dir, uint32_t class, uint64_t flags)
{
	function_called();
}

void __wrap_metadata_io_end(struct ocf_io *io, int error)
{
}

void __wrap_ocf_io_set_cmpl(struct ocf_io *io, void *context,
                void *context2, ocf_end_io_t fn)
{
	function_called();
}

int __wrap_ocf_io_set_data(struct ocf_io *io, ctx_data_t *data,
                uint32_t offset)
{
	function_called();
	return mock();
}

void __wrap_ocf_volume_submit_io(struct ocf_io *io)
{
	function_called();
}

void __wrap_ctx_data_free(ocf_ctx_t ctx, ctx_data_t *data)
{
	function_called();
}

void __wrap_ocf_io_put(struct ocf_io *io)
{
	function_called();
}

int __wrap_ocf_restart_meta_io(struct ocf_request *req)
{
}

void __wrap_env_atomic_inc(env_atomic *a)
{
	function_called();
}

static void metadata_submit_io_test01(void **state)
{
        int result;
        struct metadata_io mio;
        struct ocf_cache cache;
        uint32_t count;
        uint32_t written;

        print_test_description("Couldn't allocate new IO");

        expect_function_call(__wrap_ocf_new_cache_io);
        will_return(__wrap_ocf_new_cache_io, 0);

        result = metadata_submit_io(&cache, &mio, count, written);

        assert_int_equal(result, -ENOMEM);
        assert_int_equal(mio.error, -ENOMEM);
}

static void metadata_submit_io_test02(void **state)
{
        int result;
        struct metadata_io mio;
        struct ocf_cache cache;
        uint32_t count;
        uint32_t written;

        print_test_description("Couldn't allocate data buffer for IO");

        expect_function_call(__wrap_ocf_new_cache_io);
        will_return(__wrap_ocf_new_cache_io, 1);

        expect_function_call(__wrap_ctx_data_alloc);
        will_return(__wrap_ctx_data_alloc, 0);

        expect_function_call(__wrap_ocf_io_put);

        result = metadata_submit_io(&cache, &mio, count, written);

        assert_int_equal(result, -ENOMEM);
        assert_int_equal(mio.error, -ENOMEM);
}

static void metadata_submit_io_test03(void **state)
{
        int result;
        struct metadata_io mio;
        struct ocf_cache cache;
        uint32_t count;
        uint32_t written;
        int mio_err = 0;

        print_test_description("Write operation is performed successfully");

        mio.hndl_fn = __wrap_metadata_io_write_fill;

        mio.dir = OCF_WRITE;
        mio.error = mio_err;
        count = 1;

        expect_function_call(__wrap_ocf_new_cache_io);
        will_return(__wrap_ocf_new_cache_io, 1);

        expect_function_call(__wrap_ctx_data_alloc);
        will_return(__wrap_ctx_data_alloc, 1);

        expect_function_call(__wrap_metadata_io_write_fill);
        will_return(__wrap_metadata_io_write_fill, 0);

        expect_function_call(__wrap_ocf_io_configure);

        expect_function_call(__wrap_ocf_io_set_cmpl);

        expect_function_call(__wrap_ocf_io_set_data);
        will_return(__wrap_ocf_io_set_data, 0);

        expect_function_call(__wrap_env_atomic_inc);

        expect_function_call(__wrap_ocf_volume_submit_io);

        result = metadata_submit_io(&cache, &mio, count, written);

        assert_int_equal(result, 0);
        assert_int_equal(mio.error, mio_err);
}

static void metadata_submit_io_test04(void **state)
{
        int result;
        int i;
        int interations_before_fail;
        struct metadata_io mio;
        struct ocf_cache cache;
        uint32_t count;
        uint32_t written;

        print_test_description("Write operation is performed, but if fails at 3rd iteration");

        mio.hndl_fn = __wrap_metadata_io_write_fill;

        mio.dir = OCF_WRITE;
        count = 3;
        interations_before_fail = 2;

        expect_function_call(__wrap_ocf_new_cache_io);
        will_return(__wrap_ocf_new_cache_io, 1);

        expect_function_call(__wrap_ctx_data_alloc);
        will_return(__wrap_ctx_data_alloc, 1);

        for (i = 0; i < interations_before_fail; i++) {
                expect_function_call(__wrap_metadata_io_write_fill);
                will_return(__wrap_metadata_io_write_fill, 0);
        }

        expect_function_call(__wrap_metadata_io_write_fill);
        will_return(__wrap_metadata_io_write_fill, 1);

        expect_function_call(__wrap_ctx_data_free);

        expect_function_call(__wrap_ocf_io_put);

        result = metadata_submit_io(&cache, &mio, count, written);

        assert_int_equal(result, 1);
        assert_int_equal(mio.error, 1);
}


/*
 * Main function. It runs tests.
 */
int main(void)
{
        const struct CMUnitTest tests[] = {
		cmocka_unit_test(metadata_submit_io_test01),
		cmocka_unit_test(metadata_submit_io_test02),
		cmocka_unit_test(metadata_submit_io_test03),
		cmocka_unit_test(metadata_submit_io_test04)
        };

        print_message("Example template for tests\n");

        return cmocka_run_group_tests(tests, NULL, NULL);
}

