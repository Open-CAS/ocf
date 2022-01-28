#!/usr/bin/env python3

#
# Copyright(c) 2012 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import sys
import random


with open("config/random.cfg", "w") as f:
    f.write(str(random.randint(0, sys.maxsize)))
