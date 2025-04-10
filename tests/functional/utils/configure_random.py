#!/usr/bin/env python3

#
# Copyright(c) 2012-2021 Intel Corporation
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

import os
import sys
import random

if not os.path.exists('config'):
    os.mkdir('config')

with open("config/random.cfg", "w") as f:
    f.write(str(random.randint(0, sys.maxsize)))
