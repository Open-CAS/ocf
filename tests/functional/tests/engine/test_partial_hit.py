#
# Copyright(c) 2024 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest


from pyocf.types.data import Data, DataSeek
from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.shared import CacheLineSize
from pyocf.types.volume import RamVolume, Volume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size
from pyocf.types.io import IoDir


@pytest.mark.parametrize("cacheline_size", CacheLineSize)
@pytest.mark.parametrize("cache_mode", CacheMode)
def test_partial_hit_write(pyocf_ctx, cacheline_size, cache_mode):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(
        cache_device, cache_line_size=cacheline_size, cache_mode=cache_mode
    )
    core = Core.using_device(core_device)

    queue = cache.get_default_queue()

    cache.add_core(core)
    core_volume = CoreVolume(core)
    core_volume.open()

    # Fill core with data
    CL = cache.cache_line_size
    data = Data(CL // 2)
    data.seek(DataSeek.BEGIN, 0)
    data.write(b"A\x00\x00\x00\x00", 5)
    core_device.sync_io(queue, 0, data, IoDir.WRITE)
    core_device.sync_io(queue, CL // 2, data, IoDir.WRITE)

    # Write 0.5 CL
    data.seek(DataSeek.BEGIN, 0)
    data.write(b"B\x00\x00\x00\x00", 5)
    core_volume.sync_io(queue, 0, data, IoDir.WRITE)

    data1 = core_volume.read_sync(queue, 0, CL)

    assert chr(data1[0]) == "B"
    assert chr(data1[CL // 2]) == "A"


@pytest.mark.parametrize("cacheline_size", CacheLineSize)
@pytest.mark.parametrize("cache_mode", CacheMode)
def test_partial_hit_read(pyocf_ctx, cacheline_size, cache_mode):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(
        cache_device, cache_line_size=cacheline_size, cache_mode=cache_mode
    )
    core = Core.using_device(core_device)

    queue = cache.get_default_queue()

    cache.add_core(core)
    core_volume = CoreVolume(core)
    core_volume.open()

    # Fill core with data
    CL = cache.cache_line_size
    data = Data(CL // 2)
    data.seek(DataSeek.BEGIN, 0)
    data.write(b"A\x00\x00\x00\x00", 5)
    core_device.sync_io(queue, 0, data, IoDir.WRITE)
    core_device.sync_io(queue, CL // 2, data, IoDir.WRITE)

    data_read = Data(CL // 2)
    core_volume.sync_io(queue, 0, data_read, IoDir.READ)

    data1 = core_volume.read_sync(queue, 0, CL)

    assert chr(data1[0]) == "A"
    assert chr(data1[CL // 2]) == "A"


@pytest.mark.parametrize("cacheline_size", CacheLineSize)
@pytest.mark.parametrize("cache_mode", [CacheMode.WB, CacheMode.WO])
def test_read_partial_hit_partial_invalidate_dirty(pyocf_ctx, cacheline_size, cache_mode):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(
        cache_device, cache_line_size=cacheline_size, cache_mode=cache_mode
    )
    core = Core.using_device(core_device)

    queue = cache.get_default_queue()

    cache.add_core(core)
    core_volume = CoreVolume(core)
    core_volume.open()

    CL = cache.cache_line_size
    data = Data(CL)
    data.seek(DataSeek.BEGIN, 0)
    data.write(b"A" * CL, CL)
    core_volume.sync_io(queue, 0, data, IoDir.WRITE)

    data.seek(DataSeek.BEGIN, 0)
    data.write(b"B" * 512, 512)
    core_volume.sync_io(queue, 512, data, IoDir.WRITE)

    data1 = core_volume.read_sync(queue, 0, CL)

    assert chr(data1[0]) == "A"
    assert chr(data1[512]) == "B"
    assert chr(data1[1023]) == "B"
    assert chr(data1[1024]) == "A"


@pytest.mark.parametrize("cacheline_size", CacheLineSize)
def test_partial_hit_backfill(pyocf_ctx, cacheline_size):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(cache_device, cache_line_size=cacheline_size)
    core = Core.using_device(core_device)

    queue = cache.get_default_queue()

    cache.add_core(core)
    core_volume = CoreVolume(core)
    core_volume.open()

    cache_device.reset_stats()
    core_device.reset_stats()

    CL = cache.cache_line_size
    # Populate core backend volume
    invalid_sectors = list(range(0, 6 * CL, Size._SECTOR_SIZE))
    prefill_data = Data(Size._SECTOR_SIZE)
    prefill_data.write(b"I\x00\x00\x00\x00", 5)
    for addr in invalid_sectors:
        core_device.sync_io(queue, addr, prefill_data, IoDir.WRITE)

    stats = cache_device.get_stats()
    assert stats[IoDir.WRITE] == 0

    # Write data to the core
    core_data_addr = 2 * CL + CL // 2
    core_data_size = CL
    valid_sectors = list(range(core_data_addr, core_data_addr + core_data_size, Size._SECTOR_SIZE))
    valid_data = Data(core_data_size)
    for addr in range(0, CL, Size._SECTOR_SIZE):
        valid_data.seek(DataSeek.BEGIN, addr)
        valid_data.write(b"C\x00\x00\x00\x00", 5)
    core_volume.sync_io(queue, core_data_addr, valid_data, IoDir.WRITE)

    invalid_sectors = [s for s in invalid_sectors if s not in valid_sectors]

    read_data = core_volume.read_sync(queue, 0, 6 * CL)
    for addr in invalid_sectors:
        assert chr(read_data[addr]) == "I", f"data offset {addr}"

    for addr in valid_sectors:
        assert chr(read_data[addr]) == "C", f"data offset {addr}"
