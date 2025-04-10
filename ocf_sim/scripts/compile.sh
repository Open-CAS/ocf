#!/bin/bash
#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

cd ..
make distclean
make -j 2>&1
if [ $? -ne 0 ]; then
        echo "Error: Compilation Failed"
        exit 1
fi
