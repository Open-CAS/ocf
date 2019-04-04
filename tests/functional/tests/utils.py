#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import random
import string
from pyocf.utils import Size
from pyocf.types.volume import Volume
from pyocf.types.cache import Cache
from pyocf.types.core import Core
from ctypes import (
    c_uint64,
    c_uint32,
    c_uint16,
    c_int,
    c_uint
)


def generate_random_numbers(c_type, count=1000):
    type_dict = {
        c_uint16: [0, c_uint16(-1).value],
        c_uint32: [0, c_uint32(-1).value],
        c_uint64: [0, c_uint64(-1).value],
        c_int: [int(-c_uint(-1).value / 2) - 1, int(c_uint(-1).value / 2)]
    }

    values = []
    for i in range(0, count):
        values.append(random.randint(type_dict[c_type][0], type_dict[c_type][1]))
    return values


def generate_random_strings():
    values = []
    for t in [string.digits,
              string.ascii_letters + string.digits,
              string.ascii_lowercase,
              string.ascii_uppercase,
              string.printable,
              string.punctuation,
              string.hexdigits]:
        for i in range(0, 100):
            values.append(''.join(random.choice(t) for _ in range(random.randint(0, 20))))
    return values


def get_random_ints(c_type):
    for value in generate_random_numbers(c_type):
        yield value


def get_random_strings():
    for value in generate_random_strings():
        yield value


def start_cache_with_core(cache_size: Size, core_size: Size, **config):
    cache_device = Volume(cache_size)
    core_device = Volume(core_size)
    cache = Cache.start_on_device(cache_device, **config)
    core = Core.using_device(core_device)
    cache.add_core(core)
    cache_device.reset_stats()
    core_device.reset_stats()
    return cache_device, core_device, cache, core
