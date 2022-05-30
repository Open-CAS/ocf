#
# Copyright(c) 2020-2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import c_int, memmove, cast, c_void_p
from enum import IntEnum
from itertools import product
import random

import pytest

from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.utils import Size
from pyocf.types.shared import OcfCompletion


def __io(io, queue, address, size, data, direction):
    io.set_data(data, 0)
    completion = OcfCompletion([("err", c_int)])
    io.callback = completion.callback
    io.submit()
    completion.wait()
    return int(completion.results["err"])


def io_to_exp_obj(core, address, size, data, offset, direction, flags):
    vol = core.get_front_volume()
    queue = core.cache.get_default_queue()
    io = vol.new_io(queue, address, size, direction, 0, flags)
    if direction == IoDir.READ:
        _data = Data.from_bytes(bytes(size))
    else:
        _data = Data.from_bytes(data, offset, size)
    ret = __io(io, queue, address, size, _data, direction)
    if not ret and direction == IoDir.READ:
        memmove(cast(data, c_void_p).value + offset, _data.handle, size)
    return ret


class FlagsValVolume(RamVolume):
    def __init__(self, size, flags):
        self.flags = flags
        self.check = False
        self.fail = False
        super().__init__(size)

    def set_check(self, check):
        self.check = check

    def submit_io(self, io):
        if self.check:
            flags = io.contents._flags
            if flags != self.flags:
                self.fail = True
        super().submit_io(io)


@pytest.mark.parametrize("cache_mode", CacheMode)
def test_io_flags(pyocf_ctx, cache_mode):
    """
    Verify that I/O flags provided at the top volume interface
    are propagated down to bottom volumes for all associated
    I/Os (including metadata writes to cache volume).
    """

    flags = 0x239482
    block_size = 4096

    data = bytes(block_size)

    pyocf_ctx.register_volume_type(FlagsValVolume)

    cache_device = FlagsValVolume(Size.from_MiB(50), flags)
    core_device = FlagsValVolume(Size.from_MiB(50), flags)

    cache = Cache.start_on_device(cache_device, cache_mode=cache_mode)
    core = Core.using_device(core_device)

    cache.add_core(core)
    vol = CoreVolume(core, open=True)

    cache_device.set_check(True)
    core_device.set_check(True)

    # write miss
    io_to_exp_obj(core, block_size * 0, block_size, data, 0, IoDir.WRITE, flags)
    assert not cache_device.fail
    assert not core_device.fail

    # read miss
    io_to_exp_obj(core, block_size * 1, block_size, data, 0, IoDir.READ, flags)
    assert not cache_device.fail
    assert not core_device.fail

    # "dirty" read hit
    io_to_exp_obj(core, block_size * 0, block_size, data, 0, IoDir.READ, flags)
    assert not cache_device.fail
    assert not core_device.fail

    # "clean" read hit
    io_to_exp_obj(core, block_size * 1, block_size, data, 0, IoDir.READ, flags)
    assert not cache_device.fail
    assert not core_device.fail

    # "dirty" write hit
    io_to_exp_obj(core, block_size * 0, block_size, data, 0, IoDir.WRITE, flags)
    assert not cache_device.fail
    assert not core_device.fail

    # "clean" write hit
    io_to_exp_obj(core, block_size * 1, block_size, data, 0, IoDir.WRITE, flags)
    assert not cache_device.fail
    assert not core_device.fail
