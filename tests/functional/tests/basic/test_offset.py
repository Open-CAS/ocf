#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

#
# Test core volume set_data() with offset!=0
#
from pyocf.types.cache import Cache
from pyocf.types.core import Core
from pyocf.types.data import Data, DataSeek
from pyocf.types.io import IoDir, Sync
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size as S
from pyocf.ocf_utils import core_sync_read, volume_sync_read


def test_data_with_offset(pyocf_ctx):
    cache_device = RamVolume(S.from_MiB(50))
    core_device = RamVolume(S.from_MiB(50))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)
    queue = cache.get_default_queue()

    cache.add_core(core)
    volume = CoreVolume(core)
    volume.open()

    # write using data with offset
    B1 = b'12345'
    B2 = b'67890'
    data = Data(8192)
    data.seek(DataSeek.BEGIN, 0)
    data.write(B1, len(B1))
    data.seek(DataSeek.BEGIN, 4096)
    data.write(B2, len(B2))

    addr = 4096
    length = 4096
    offset = 4096
    io = volume.new_io(queue, addr, length, IoDir.WRITE, 0, 0)
    io.set_data(data, offset)
    Sync(io).submit()

    # normal read
    s = core_sync_read(core, 4096, len(B2))
    assert s == B2

    s = volume_sync_read(core_device, queue, 4096, len(B2))
    assert s == B2

    # read using data with offset
    data1 = Data(10000)
    offset1 = 10
    io1 = volume.new_io(queue, addr, length, IoDir.READ, 0, 0)
    io1.set_data(data1, offset1)
    Sync(io1).submit()

    s0 = data1.buffer[:offset1]
    assert s0 == bytes([Data.DATA_POISON] * offset1)
    s1 = data1.buffer[offset1:(offset1 + len(B2))]
    assert s1 == B2

    volume.close()
    cache.stop()
