#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import os
import sys
from ctypes import (
    c_uint64,
    c_uint32,
    c_uint16,
    c_int
)
from tests.utils.random import RandomStringGenerator, RandomGenerator, DefaultRanges

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), os.path.pardir))


@pytest.fixture(params=RandomGenerator(DefaultRanges.UINT16))
def c_uint16_randomize(request):
    return request.param


@pytest.fixture(params=RandomGenerator(DefaultRanges.UINT32))
def c_uint32_randomize(request):
    return request.param


@pytest.fixture(params=RandomGenerator(DefaultRanges.UINT64))
def c_uint64_randomize(request):
    return request.param


@pytest.fixture(params=RandomGenerator(DefaultRanges.INT))
def c_int_randomize(request):
    return request.param


@pytest.fixture(params=RandomGenerator(DefaultRanges.INT))
def c_int_sector_randomize(request):
    return request.param // 512 * 512


@pytest.fixture(params=RandomStringGenerator())
def string_randomize(request):
    return request.param
