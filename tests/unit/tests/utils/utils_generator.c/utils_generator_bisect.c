/*
 * Copyright(c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * <tested_file_path>src/utils/utils_generator.c</tested_file_path>
 * <tested_function>ocf_generator_bisect_next</tested_function>
 * <functions_to_leave>
 *  bitreverse32
 *  ocf_generator_bisect_init
 * </functions_to_leave>
 */

#undef static

#undef inline


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "print_desc.h"

#include "utils_generator.h"

#include "utils/utils_generator.c/utils_generator_bisect_generated_wraps.c"

static void ocf_generator_bisect_test01(void **state)
{
	struct {
		uint32_t values[16];
		uint32_t limit;
	} expected_output[] = {
		{
			.values = { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 },
			.limit = 16,
		},
		{
			.values = { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7 },
			.limit = 15,
		},
		{
			.values = { 0, 8, 4, 12, 2, 10, 6, 1, 9, 5, 13, 3, 11, 7 },
			.limit = 14,
		},
		{
			.values = { 0, 8, 4, 12, 2, 10, 6, 1, 9, 5, 3, 11, 7 },
			.limit = 13,
		},
		{
			.values = { 0, 8, 4, 2, 10, 6, 1, 9, 5, 3, 11, 7 },
			.limit = 12,
		},
		{
			.values = { 0, 8, 4, 2, 10, 6, 1, 9, 5, 3, 7 },
			.limit = 11,
		},
		{
			.values = { 0, 8, 4, 2, 6, 1, 9, 5, 3, 7 },
			.limit = 10,
		},
		{
			.values = { 0, 8, 4, 2, 6, 1, 5, 3, 7 },
			.limit = 9,
		},
		{
			.values = { 0, 4, 2, 6, 1, 5, 3, 7 },
			.limit = 8,
		},
		{
			.values = { 0, 4, 2, 6, 1, 5, 3 },
			.limit = 7,
		},
		{
			.values = { 0, 4, 2, 1, 5, 3 },
			.limit = 6,
		},
		{
			.values = { 0, 4, 2, 1, 3 },
			.limit = 5,
		},
		{
			.values = { 0, 2, 1, 3 },
			.limit = 4,
		},
		{
			.values = { 0, 2, 1 },
			.limit = 3,
		},
		{
			.values = { 0, 1 },
			.limit = 2,
		},
		{
			.values = { 0 },
			.limit = 1,
		},
	};
	struct ocf_generator_bisect_state generator;
	uint32_t value;
	int i, j;

	print_test_description("Check if sequence order is correct");

	for (i = 0; i < sizeof(expected_output)/sizeof(*expected_output); i++) {
		ocf_generator_bisect_init(&generator,
				expected_output[i].limit, 0);

		for (j = 0; j < expected_output[i].limit; j++) {
			value = ocf_generator_bisect_next(&generator);
			assert_int_equal(value, expected_output[i].values[j]);
		}
	}
}

static void ocf_generator_bisect_test02(void **state)
{
	struct {
		uint32_t values[16];
		uint32_t limit;
		uint32_t offset;
	} expected_output[] = {
		{
			.values = { 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15, 0 },
			.limit = 16,
			.offset = 1,
		},
		{
			.values = { 15, 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7 },
			.limit = 16,
			.offset = 15,
		},
		{
			.values = { 1, 9, 5, 13, 3, 11, 7, 15, 0, 8, 4, 12, 2, 10, 6, 14 },
			.limit = 16,
			.offset = 8,
		},
		{
			.values = { 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 0 },
			.limit = 15,
			.offset = 1,
		},
		{
			.values = { 7, 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11 },
			.limit = 15,
			.offset = 14,
		},
		{
			.values = { 1, 9, 5, 13, 3, 11, 7, 0, 8, 4, 12, 2, 10, 6, 14 },
			.limit = 15,
			.offset = 8,
		},
		{
			.values = { 8, 4, 2, 10, 6, 1, 9, 5, 3, 11, 7, 0 },
			.limit = 12,
			.offset = 1,
		},
		{
			.values = { 7, 0, 8, 4, 2, 10, 6, 1, 9, 5, 3, 11 },
			.limit = 12,
			.offset = 11,
		},
		{
			.values = { 1, 9, 5, 3, 11, 7, 0, 8, 4, 2, 10, 6 },
			.limit = 12,
			.offset = 6,
		},
		{
			.values = { 8, 4, 2, 6, 1, 5, 3, 7, 0 },
			.limit = 9,
			.offset = 1,
		},
		{
			.values = { 7, 0, 8, 4, 2, 6, 1, 5, 3 },
			.limit = 9,
			.offset = 8,
		},
		{
			.values = { 1, 5, 3, 7, 0, 8, 4, 2, 6 },
			.limit = 9,
			.offset = 5,
		},
	};
	struct ocf_generator_bisect_state generator;
	uint32_t value;
	int i, j;

	print_test_description("Check if offset works correctly");

	for (i = 0; i < sizeof(expected_output)/sizeof(*expected_output); i++) {
		ocf_generator_bisect_init(&generator,
				expected_output[i].limit,
				expected_output[i].offset);

		for (j = 0; j < expected_output[i].limit; j++) {
			value = ocf_generator_bisect_next(&generator);
			assert_int_equal(value, expected_output[i].values[j]);
		}
	}
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_generator_bisect_test01),
		cmocka_unit_test(ocf_generator_bisect_test02),
	};

	print_message("Unit tests for generator bisect\n");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
