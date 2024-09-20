#
# Copyright(c) 2020-2022 Intel Corporation
# Copyright(c) 2024 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import memmove, cast, c_void_p, c_uint64

import pytest

from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.types.data import Data
from pyocf.types.io import IoDir, Sync
from pyocf.utils import Size
from pyocf.ocf import OcfLib


def __io(io, data):
    io.set_data(data, 0)
    completion = Sync(io).submit()
    return int(completion.results["err"])


def io_to_exp_obj(vol, address, size, data, offset, direction, flags):
    queue = vol.parent.get_default_queue()
    vol.open()
    io = vol.new_io(queue, address, size, direction, 0, flags)
    if direction == IoDir.READ:
        _data = Data.from_bytes(bytes(size))
    else:
        _data = Data.from_bytes(data, offset, size)
    ret = __io(io, _data)
    if not ret and direction == IoDir.READ:
        memmove(cast(data, c_void_p).value + offset, _data.handle, size)
    vol.close()
    return ret


class FlagsValVolume(RamVolume):
    def __init__(self, size, flags):
        self.flags = flags
        self.check = False
        self.fail = False
        super().__init__(size)

    def set_check(self):
        self.check = True
        self.fail = True

    def do_forward_io(self, token, rw, addr, nbytes, offset):
        if self.check:
            flags = lib.ocf_forward_get_flags(token)
            if flags == self.flags:
                self.fail = False
        super().do_forward_io(token, rw, addr, nbytes, offset)


def test_io_flags(pyocf_ctx):
    """
    Verify that I/O flags provided at the top volume interface
    are propagated down to bottom volumes for all associated
    I/Os (including metadata writes to cache volume).
    """

    flags = 0x239482
    block_size = 4096

    data = bytes(block_size)

    pyocf_ctx.register_volume_type(FlagsValVolume)

    cache_device = FlagsValVolume(Size.from_MiB(50), 0)
    core_device = FlagsValVolume(Size.from_MiB(50), flags)

    cache = Cache.start_on_device(cache_device, cache_mode=CacheMode.WB)
    core = Core.using_device(core_device)

    cache.add_core(core)
    vol = CoreVolume(core)

    def set_check():
        cache_device.set_check()
        core_device.set_check()

    # write miss
    set_check()
    io_to_exp_obj(vol, block_size * 0, block_size, data, 0, IoDir.WRITE, flags)
    assert not cache_device.fail

    # read miss
    set_check()
    io_to_exp_obj(vol, block_size * 1, block_size, data, 0, IoDir.READ, flags)
    assert not core_device.fail

    # "dirty" read hit
    set_check()
    io_to_exp_obj(vol, block_size * 0, block_size, data, 0, IoDir.READ, flags)
    assert not cache_device.fail

    # "clean" read hit
    set_check()
    io_to_exp_obj(vol, block_size * 1, block_size, data, 0, IoDir.READ, flags)
    assert not cache_device.fail

    cache.change_cache_mode(CacheMode.WT)

    # "dirty" write hit
    set_check()
    io_to_exp_obj(vol, block_size * 0, block_size, data, 0, IoDir.WRITE, flags)
    assert not cache_device.fail
    assert not core_device.fail

    # "clean" write hit
    set_check()
    io_to_exp_obj(vol, block_size * 1, block_size, data, 0, IoDir.WRITE, flags)
    assert not cache_device.fail
    assert not core_device.fail


lib = OcfLib.getInstance()
lib.ocf_forward_get_flags.argtypes = [c_uint64]
lib.ocf_forward_get_flags.restype = c_uint64
