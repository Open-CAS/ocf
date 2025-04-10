#!/bin/bash
#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

if [ $# -lt 1 ]; then
        echo "usage: $0 <ocf-sim - new file name>"
        echo "       it compiles, renames ocf-sim,"
        echo "       runs it and produces required report"
        exit 1
fi

if [ `hostname` != "fci9" ]; then
        echo "Run script while connected to FCI9";
        exit 1
fi

if [ `basename $(pwd)` != scripts ]; then
        echo "Run script from 'scripts' directory";
        exit 1
fi

./compile.sh || exit 2
./rename.sh $1
./runall.sh $1
./report.sh $1
