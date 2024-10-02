#
# Copyright(c) 2024 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest

from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume, ErrorDevice
from pyocf.types.volume_core import CoreVolume
from pyocf.types.shared import CacheLineSize
from pyocf.utils import Size
from pyocf.rio import Rio, ReadWrite

BLOCK_SIZES = [Size(512), Size.from_KiB(1), Size.from_KiB(4), Size.from_KiB(64), Size.from_KiB(256)]


@pytest.mark.parametrize("cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_64KiB])
@pytest.mark.parametrize("cache_mode", [c for c in CacheMode if not c.lazy_write()])
@pytest.mark.parametrize("rio_bs", BLOCK_SIZES)
def test_strict_engine_errors(pyocf_ctx, cache_mode: CacheMode, cls: CacheLineSize, rio_bs: Size):
    cache_vol_size = Size.from_MiB(50)
    ram_cache_volume = RamVolume(cache_vol_size)
    error_sectors = set(x for x in range(0, cache_vol_size, 512))
    error_device = ErrorDevice(ram_cache_volume, error_sectors, armed=False)
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(error_device, cache_mode=cache_mode)
    core = Core.using_device(core_device)
    queue = cache.get_default_queue()

    cache.add_core(core)
    core_volume = CoreVolume(core)
    core_volume.open()

    error_device.reset_stats()
    error_device.arm()

    rio_size = Size.from_MiB(3) if rio_bs > Size(4096) else Size.from_MiB(1)

    read_rio_stats = (
        Rio()
        .target(core_volume)
        .njobs(1)
        .readwrite(ReadWrite.RANDREAD)
        .size(rio_size)
        .bs(rio_bs)
        .qd(16)
        .continue_on_error()
        .run([queue])
    )

    # FIXME: Get rid of the second Rio instance, once the real RANDRW support is
    # implemented in Rio
    write_rio_stats = (
        Rio()
        .target(core_volume)
        .njobs(1)
        .readwrite(ReadWrite.RANDWRITE)
        .size(rio_size)
        .bs(rio_bs)
        .qd(16)
        .continue_on_error()
        .run([queue])
    )

    cache.settle()

    assert cache.get_stats()["usage"]["occupancy"]["value"] == 0

    assert read_rio_stats.error_count == 0
    assert write_rio_stats.error_count == 0

    if cache_mode is CacheMode.PT:
        expected_cache_write_errors = 0
    else:
        expected_cache_write_errors = write_rio_stats.submitted_writes

    actual_cache_write_errors = cache.get_stats()["errors"]["cache_volume_wr"]["value"]

    assert actual_cache_write_errors >= expected_cache_write_errors

    error_device.disarm()


@pytest.mark.parametrize("cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_64KiB])
@pytest.mark.parametrize("cache_mode", [c for c in CacheMode if c.lazy_write()])
@pytest.mark.parametrize("rio_bs", BLOCK_SIZES)
def test_lazy_engine_errors(pyocf_ctx, cache_mode: CacheMode, cls: CacheLineSize, rio_bs: Size):
    cache_vol_size = Size.from_MiB(50)
    ram_cache_volume = RamVolume(cache_vol_size)
    error_sectors = set(x for x in range(0, cache_vol_size, 512))
    error_device = ErrorDevice(ram_cache_volume, error_sectors, armed=False)
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(error_device, cache_mode=cache_mode)
    core = Core.using_device(core_device)
    queue = cache.get_default_queue()

    cache.add_core(core)
    core_volume = CoreVolume(core)
    core_volume.open()

    error_device.reset_stats()
    error_device.arm()

    rio_size = Size.from_MiB(3) if rio_bs > Size(4096) else Size.from_MiB(1)

    read_rio_stats = (
        Rio()
        .target(core_volume)
        .njobs(1)
        .readwrite(ReadWrite.RANDREAD)
        .size(rio_size)
        .bs(rio_bs)
        .qd(16)
        .continue_on_error()
        .run([queue])
    )

    # FIXME: Get rid of the second Rio instance, once the real RANDRW support is
    # implemented in Rio
    write_rio_stats = (
        Rio()
        .target(core_volume)
        .njobs(1)
        .readwrite(ReadWrite.RANDWRITE)
        .size(rio_size)
        .bs(rio_bs)
        .qd(16)
        .continue_on_error()
        .run([queue])
    )

    cache.settle()

    assert cache.get_stats()["usage"]["occupancy"]["value"] == 0

    assert read_rio_stats.error_count == 0
    assert write_rio_stats.error_count == write_rio_stats.submitted_writes

    expected_cache_write_errors = write_rio_stats.submitted_writes
    actual_cache_write_errors = cache.get_stats()["errors"]["cache_volume_wr"]["value"]

    assert actual_cache_write_errors >= expected_cache_write_errors

    error_device.disarm()
