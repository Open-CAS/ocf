#
# Copyright(c) 2024 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#

from pyocf.types.cache import Cache
from pyocf.types.core import Core
from pyocf.types.data import Data, DataSeek
from pyocf.types.io import IoDir, Sync
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size


def test_data_with_offset(pyocf_ctx):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)
    queue = cache.get_default_queue()

    cache.add_core(core)
    core_volume = CoreVolume(core)
    core_volume.open()

    # Populate core backend volume
    CL = cache.cache_line_size
    data_1 = Data(CL)
    for addr in range(0, CL, Size._SECTOR_SIZE):
        data_1.seek(DataSeek.BEGIN, addr)
        data_1.write(b"I\x00\x00\x00\x00", 5)
    core_device.sync_io(queue, CL * 0, data_1, IoDir.WRITE)
    core_device.sync_io(queue, CL * 1, data_1, IoDir.WRITE)
    core_device.sync_io(queue, CL * 2, data_1, IoDir.WRITE)
    core_device.sync_io(queue, CL * 3, data_1, IoDir.WRITE)

    # write using data with offset
    B1 = b"12345"
    B2 = b"67890"
    data = Data(8192)
    data.seek(DataSeek.BEGIN, 0)
    data.write(B1, len(B1))
    data.seek(DataSeek.BEGIN, 4096)
    data.write(B2, len(B2))

    address = CL
    length = CL
    offset = CL
    io = core_volume.new_io(queue, address, length, IoDir.WRITE, 0, 0)
    io.set_data(data, offset)
    Sync(io).submit()

    s = core_device.read_sync(queue, 0, 2 * CL)
    for addr in range(0, CL, Size._SECTOR_SIZE):
        assert chr(s[addr]) == "I", f"addr {addr}"
    assert s[CL:CL + len(B2)] == B2

    s = core_volume.read_sync(queue, 0, 2 * CL)
    for addr in range(0, CL, Size._SECTOR_SIZE):
        assert chr(s[addr]) == "I", f"addr {addr}"
    assert s[CL:CL + len(B2)] == B2

    # read using data with offset
    data1 = Data(10000)
    offset1 = 10
    io1 = core_volume.new_io(queue, address, length, IoDir.READ, 0, 0)
    io1.set_data(data1, offset1)
    Sync(io1).submit()

    s0 = data1.buffer[:offset1]
    assert s0 == bytes([Data.DATA_POISON] * offset1)
    s1 = data1.buffer[offset1:(offset1 + len(B2))]
    assert s1 == B2
