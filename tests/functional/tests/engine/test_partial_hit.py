#
# Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import pytest

from pyocf.types.data import Data, DataSeek
from pyocf.ocf_utils import ReadMode, WriteMode, assert_device, core_sync_read, core_sync_write, volume_sync_write
from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.shared import CacheLineSize
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size

@pytest.mark.parametrize("cacheline_size", CacheLineSize)
@pytest.mark.parametrize("cache_mode", CacheMode)
def test_partial_hit_write(pyocf_ctx, cacheline_size, cache_mode):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(cache_device, metadata_volatile=True,
                                  cache_line_size=cacheline_size, cache_mode=cache_mode)
    core = Core.using_device(core_device)

    queue = cache.get_default_queue()

    cache.add_core(core)
    volume = CoreVolume(core)
    volume.open()

    # Fill core with data
    CL=cache.cache_line_size
    data = Data(CL//2)
    data.seek(DataSeek.BEGIN, 0)
    data.write(b'A\x00\x00\x00\x00', 5)
    volume_sync_write(core_device, queue, 0, data, mode=WriteMode.BINARY)
    volume_sync_write(core_device, queue, CL//2, data, mode=WriteMode.BINARY)

    # Write 0.5 CL
    data.seek(DataSeek.BEGIN, 0)
    data.write(b'B\x00\x00\x00\x00', 5)
    core_sync_write(core, 0, data, mode=WriteMode.BINARY)

    data1 = core_sync_read(core, 0, CL, mode=ReadMode.STRING)

    assert chr(data1[0]) == 'B'
    assert chr(data1[CL//2]) == 'A'


@pytest.mark.parametrize("cacheline_size", CacheLineSize)
@pytest.mark.parametrize("cache_mode", CacheMode)
def test_partial_hit_read(pyocf_ctx, cacheline_size, cache_mode):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(cache_device, metadata_volatile=True,
                                  cache_line_size=cacheline_size, cache_mode=cache_mode)
    core = Core.using_device(core_device)

    queue = cache.get_default_queue()

    cache.add_core(core)
    volume = CoreVolume(core)
    volume.open()

    # Fill core with data
    CL=cache.cache_line_size
    data = Data(CL//2)
    data.seek(DataSeek.BEGIN, 0)
    data.write(b'A\x00\x00\x00\x00', 5)
    volume_sync_write(core_device, queue, 0, data, mode=WriteMode.BINARY)
    volume_sync_write(core_device, queue, CL//2, data, mode=WriteMode.BINARY)

    core_sync_read(core, 0, CL//2, mode=ReadMode.STRING)

    data1 = core_sync_read(core, 0, CL, mode=ReadMode.STRING)

    assert chr(data1[0]) == 'A'
    assert chr(data1[CL//2]) == 'A'


@pytest.mark.parametrize("cacheline_size", CacheLineSize)
@pytest.mark.parametrize("cache_mode", [CacheMode.WB, CacheMode.WO])
def test_read_partial_hit_partial_invalidate_dirty(pyocf_ctx, cacheline_size, cache_mode):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(cache_device, metadata_volatile=True,
                                  cache_line_size=cacheline_size, cache_mode=cache_mode)
    core = Core.using_device(core_device)

    cache.add_core(core)
    volume = CoreVolume(core)
    volume.open()

    CL=cache.cache_line_size
    data = Data(CL)
    data.seek(DataSeek.BEGIN, 0)
    data.write(b'A'*CL, CL)
    core_sync_write(core, 0, data, mode=WriteMode.BINARY)

    data.seek(DataSeek.BEGIN, 0)
    data.write(b'B'*512, 512)
    core_sync_write(core, 512, data, mode=WriteMode.BINARY)

    data1 = core_sync_read(core, 0, CL, mode=ReadMode.STRING)

    assert chr(data1[0]) == 'A'
    assert chr(data1[512]) == 'B'


def test_partial_hit_reproduce_bug(pyocf_ctx):
    ''' Reprodocfng bug when skiping hit clines on backfill,
        before adding req-status LOOKUP_HIT_INVALID,
        The case is:
        |4I|4I|C>3C|I<3I|4I|4I
        >|4I|4I|4C|4I|4I|4I<
        |4I|4I|C>3C|4I<|4I|4I
    '''
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(cache_device, metadata_volatile=True,
                                  cache_line_size=CacheLineSize.LINE_16KiB)
    core = Core.using_device(core_device)

    queue = cache.get_default_queue()

    cache.add_core(core)
    volume = CoreVolume(core)
    volume.open()

    cache_device.reset_stats()
    core_device.reset_stats()

    # Fill core with data
    CL=cache.cache_line_size
    data1 = Data(CL)
    for i in range(CL//Size._SECTOR_SIZE):
        data1.seek(DataSeek.BEGIN, i*Size._SECTOR_SIZE)
        data1.write(b'I\x00\x00\x00\x00', 5)
    volume_sync_write(core_device, queue, 0, data1, mode=WriteMode.BINARY)
    volume_sync_write(core_device, queue, CL, data1, mode=WriteMode.BINARY)

    data2 = Data(CL)
    for i in range(CL//Size._SECTOR_SIZE):
        data2.seek(DataSeek.BEGIN, i*Size._SECTOR_SIZE)
        data2.write(b'C\x00\x00\x00\x00', 5)
    core_sync_write(core, CL*2, data2, mode=WriteMode.BINARY)

    volume_sync_write(core_device, queue, CL*3, data1, mode=WriteMode.BINARY)
    volume_sync_write(core_device, queue, CL*4, data1, mode=WriteMode.BINARY)
    volume_sync_write(core_device, queue, CL*5, data1, mode=WriteMode.BINARY)

    assert_device(cache_device, 0, 1)
    assert_device(core_device, 0, 6)

    # Do the reads
    data = core_sync_read(core, int(2.25*CL), CL, mode=ReadMode.STRING)

    for j in range(3):
        assert chr(data[j*Size._SECTOR_SIZE]=='C')
    assert chr(data[3*Size._SECTOR_SIZE]=='I')

    data = core_sync_read(core, 0, 6*CL, mode=ReadMode.STRING)

    for i in range(6):
        for j in range(CL//Size._SECTOR_SIZE):
            c = chr(data[i*CL + j*Size._SECTOR_SIZE])
            if i != 2:
                assert c=='I'
            else:
                assert c=='C'

    data = core_sync_read(core, int(2.25*CL), int(1.75*CL), mode=ReadMode.STRING)
    for j in range(3):
        assert chr(data[j*Size._SECTOR_SIZE]) == 'C'
    for j in range(4):
        c = chr(data[int(0.75*CL) + j*Size._SECTOR_SIZE])
        assert c == 'I', f"j={j}, actual: {c}, expected: I"
