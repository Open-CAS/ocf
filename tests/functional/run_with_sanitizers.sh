#!/usr/bin/env bash

#
# Copyright(c) 2019-2022 Intel Corporation
# Copyright(c) 2025 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#

LIB_DIR="/lib/x86_64-linux-gnu/"

ASAN_LIB="$LIB_DIR/libasan.so.6"
TSAN_LIB="$LIB_DIR/libtsan.so.0"
UBSAN_LIB="$LIB_DIR/libubsan.so.1"

# Path to test file/directory
PYOCF_TESTS_PATH="tests/"

echo "Cleaning and building with Address Sanitizer"
make distclean
OPT_CFLAGS="-fsanitize=address" make -j >/dev/null
echo "Running tests, please wait..."
LD_PRELOAD=$ASAN_LIB ASAN_OPTIONS=log_output=asan_log.txt PYTHONMALLOC=malloc pytest $PYOCF_TESTS_PATH 2>&1 | tee asan_output.txt
echo "Done, check asan_log.txt"

echo "Cleaning and building with Thread Sanitizer"
make distclean
OPT_CFLAGS="-fsanitize=thread -fno-omit-frame-pointer" make -j >/dev/null
echo "Running tests, please wait..."
LD_PRELOAD=$TSAN_LIB TSAN_OPTIONS=log_output=tsan_log.txt pytest -s $PYOCF_TESTS_PATH 2>&1 | tee tsan_output.txt
echo "Done, check tsan_log.txt" 

echo "Cleaning and building with Undefined Behaviour Sanitizer"
make distclean
OPT_CFLAGS="-fsanitize=undefined -fno-sanitize=alignment" make -j >/dev/null
echo "Running tests, please wait..."
LD_PRELOAD=$UBSAN_LIB UBSAN_OPTIONS=log_output=ubsan_log.txt pytest -s $PYOCF_TESTS_PATH 2>&1 | tee ubsan_output.txt
echo "Done, check ubsan_output.txt" 
