#
# Copyright(c) 2023 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import pytest

from pyocf.types.cache import Cache, CacheMode, CacheLineSize
from pyocf.types.data import Data
from pyocf.types.core import Core
from pyocf.types.io import IoDir, Sync
from pyocf.types.volume import RamVolume, IoFlags, TraceDevice
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size
from math import ceil


def test_discard_propagation(pyocf_ctx):
    discards = {}

    pyocf_ctx.register_volume_type(TraceDevice)

    def trace_discard(vol, io_type, rw, addr, nbytes, flags):
        nonlocal discards

        if io_type == TraceDevice.IoType.Discard:
            if vol.uuid not in discards:
                discards[vol.uuid] = []
            discards[vol.uuid].append((addr, nbytes))

        return True

    cache_device = TraceDevice(RamVolume(Size.from_MiB(50)), trace_fcn=trace_discard)
    core_device = TraceDevice(RamVolume(Size.from_MiB(100)), trace_fcn=trace_discard)

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)
    queue = cache.get_default_queue()

    cache.add_core(core)
    volume = CoreVolume(core)
    volume.open()

    discards = {}

    addr = Size.from_MiB(2).B
    size = Size.from_MiB(1).B

    io = volume.new_io(queue, addr, size, IoDir.WRITE, 0, 0)
    data = Data(byte_count=0)
    io.set_data(data, 0)

    completion = Sync(io).submit_discard()
    volume.close()

    assert int(completion.results["err"]) == 0

    assert core_device.uuid in discards

    core_discards = discards[core_device.uuid]

    assert len(core_discards) == 1
    assert core_discards[0] == (addr, size)

    cache.stop()


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("discard_addr", [63, 64, 65])
@pytest.mark.parametrize("discard_size", [1, 127, 128, 129])
def test_discard_invalidation(pyocf_ctx, cls, discard_addr, discard_size):
    discard_addr = Size.from_KiB(discard_addr)
    discard_size = Size.from_KiB(discard_size)

    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(100))

    cache = Cache.start_on_device(cache_device, cache_line_size=cls)
    core = Core.using_device(core_device)
    queue = cache.get_default_queue()

    cache.add_core(core)
    volume = CoreVolume(core)
    volume.open()

    data_size = Size.from_KiB(256)
    pattern = b"\xff"

    data = Data(data_size)
    data.write(pattern * int(data_size), data_size)
    io = volume.new_io(queue, 0, data_size, IoDir.WRITE, 0, 0)
    io.set_data(data, 0)
    Sync(io).submit()

    data = Data(byte_count=0)
    io = volume.new_io(queue, discard_addr, discard_size, IoDir.WRITE, 0, 0)
    io.set_data(data, 0)
    Sync(io).submit_discard()

    if discard_size < cls:
        expect_occupancy = data_size
    else:
        begin = Size(ceil(int(discard_addr) / cls) * cls)
        end = min(Size((int(discard_addr + discard_size) // cls) * cls), data_size)
        expect_occupancy = data_size - (end - begin)

    assert cache.get_stats()["conf"]["occupancy"] == expect_occupancy

    data = Data(data_size)
    io = volume.new_io(queue, 0, data_size, IoDir.READ, 0, 0)
    io.set_data(data, 0)
    Sync(io).submit()

    size = int(discard_addr)
    assert bytes(data.buffer[:size]) == pattern * size

    offset = int(discard_addr + discard_size)
    size = int(data_size) - offset
    assert bytes(data.buffer[offset:]) == pattern * size

    volume.close()

    cache.stop()
