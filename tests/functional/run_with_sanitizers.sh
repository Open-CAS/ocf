#
# Copyright(c) 2019-2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

#!/usr/bin/env bash

LIB_DIR="/lib/x86_64-linux-gnu/"

ASAN_LIB="$LIB_DIR/libasan.so.6"
TSAN_LIB="$LIB_DIR/libtsan.so.0"
UBSAN_LIB="$LIB_DIR/libubsan.so.1"

TEST="tests/basic/test_pyocf.py"

echo "Cleaning and building with Address Sanitizer"
make distclean
OPT_CFLAGS="-fsanitize=address" make -j >/dev/null
echo "Running tests, please wait..."
LD_PRELOAD=$ASAN_LIB ASAN_OPTIONS=log_output=asan_log.txt pytest -s $TEST #> asan_output.txt 2>&1
echo "Done, check asan_log.txt"

echo "Cleaning and building with Thread Sanitizer"
make distclean
OPT_CFLAGS="-fsanitize=thread" make -j >/dev/null 
echo "Running tests, please wait..."
LD_PRELOAD=$TSAN_LIB TSAN_OPTIONS=log_output=tsan_log.txt pytest -s $TEST #> tsan_output.txt 2>&1
echo "Done, check tsan_log.txt" 

echo "Cleaning and building with Undefined Behaviour Sanitizer"
make distclean
OPT_CFLAGS="-fsanitize=undefined -fno-sanitize=alignment" make -j >/dev/null 
echo "Running tests, please wait..."
LD_PRELOAD=$UBSAN_LIB UBSAN_OPTIONS=log_output=ubsan_log.txt pytest -s $TEST #> ubsan_output.txt 2>&1
echo "Done, check ubsan_output.txt" 


