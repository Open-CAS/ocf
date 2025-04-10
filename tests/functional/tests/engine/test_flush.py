#
# Copyright(c) 2022-2022 Intel Corporation
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
from pyocf.types.cache import Cache
from pyocf.types.data import Data
from pyocf.types.core import Core
from pyocf.types.io import Io, IoDir, Sync
from pyocf.types.volume import RamVolume, IoFlags, TraceDevice
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size


def test_flush_propagation(pyocf_ctx):
    flushes = {}

    pyocf_ctx.register_volume_type(TraceDevice)

    def trace_flush(vol, io_type, rw, addr, nbytes, flags):
        nonlocal flushes

        if io_type == TraceDevice.IoType.Flush:
            if vol.uuid not in flushes:
                flushes[vol.uuid] = []
            flushes[vol.uuid].append((addr, nbytes))

        return True

    cache_device = TraceDevice(RamVolume(Size.from_MiB(50)), trace_fcn=trace_flush)
    core_device = TraceDevice(RamVolume(Size.from_MiB(100)), trace_fcn=trace_flush)

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)
    cache.add_core(core)

    queue = cache.get_default_queue()
    vol = CoreVolume(core)

    flushes = {}

    vol.open()
    io = vol.new_io(queue, 0, 0, IoDir.WRITE, 0, 0)

    completion = Sync(io).submit_flush()
    vol.close()

    assert int(completion.results["err"]) == 0

    assert cache_device.uuid in flushes
    assert core_device.uuid in flushes

    cache_flushes = flushes[cache_device.uuid]
    core_flushes = flushes[core_device.uuid]

    assert len(cache_flushes) == 1
    assert len(core_flushes) == 1

    cache.stop()
