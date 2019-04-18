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
from tests.utils import get_random_strings, get_random_ints

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), os.path.pardir))


@pytest.fixture(params=get_random_ints(c_uint16))
def c_uint16_randomize(request):
    return request.param


@pytest.fixture(params=get_random_ints(c_uint32))
def c_uint32_randomize(request):
    return request.param


@pytest.fixture(params=get_random_ints(c_uint64))
def c_uint64_randomize(request):
    return request.param


@pytest.fixture(params=get_random_ints(c_int))
def c_int_randomize(request):
    return request.param


@pytest.fixture(params=get_random_strings())
def string_randomize(request):
    return request.param
