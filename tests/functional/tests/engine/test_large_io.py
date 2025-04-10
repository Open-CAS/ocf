#
# Copyright(c) 2022 Intel Corporation
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import c_int

from pyocf.types.cache import Cache
from pyocf.types.data import Data
from pyocf.types.core import Core
from pyocf.types.io import IoDir, Sync
from pyocf.types.volume import RamVolume, IoFlags
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size


def test_large_flush(pyocf_ctx):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(100))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)
    cache.add_core(core)

    queue = cache.get_default_queue()
    vol = CoreVolume(core)
    vol.open()

    io = vol.new_io(queue, 0, core_device.size.bytes, IoDir.WRITE, 0, IoFlags.FLUSH)
    data = Data(byte_count=0)
    io.set_data(data, 0)
    completion = Sync(io).submit_flush()
    vol.close()

    assert int(completion.results["err"]) == 0

    cache.stop()


def test_large_discard(pyocf_ctx):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(100))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)
    cache.add_core(core)

    queue = cache.get_default_queue()
    vol = CoreVolume(core)
    vol.open()

    io = vol.new_io(queue, 0, core_device.size.bytes, IoDir.WRITE, 0, 0)
    data = Data(byte_count=0)
    io.set_data(data, 0)
    completion = Sync(io).submit_discard()
    vol.close()

    assert int(completion.results["err"]) == 0

    cache.stop()


def test_large_io(pyocf_ctx):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(100))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)
    cache.add_core(core)

    queue = cache.get_default_queue()
    vol = CoreVolume(core)
    vol.open()

    io = vol.new_io(queue, 0, core_device.size.bytes, IoDir.WRITE, 0, 0)
    data = Data(byte_count=core_device.size.bytes)
    io.set_data(data)
    completion = Sync(io).submit()

    vol.close()

    assert int(completion.results["err"]) == 0

    cache.stop()
