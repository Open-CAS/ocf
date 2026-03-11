#
# Copyright(c) 2024 Huawei Technologies
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest

from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume, ErrorDevice
from pyocf.types.volume_core import CoreVolume
from pyocf.types.shared import CacheLineSize
from pyocf.types.queue import Queue
from pyocf.utils import Size
from pyocf.rio import Rio, ReadWrite
from pyocf.helpers import is_block_size_4k

BLOCK_SIZES = [Size(512), Size.from_KiB(1), Size.from_KiB(4), Size.from_KiB(64), Size.from_KiB(256)]


@pytest.mark.parametrize("cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_64KiB])
@pytest.mark.parametrize("cache_mode", [c for c in CacheMode if not c.lazy_write()])
@pytest.mark.parametrize("rio_bs", BLOCK_SIZES)
def test_strict_engine_errors(pyocf_ctx, cache_mode: CacheMode, cls: CacheLineSize, rio_bs: Size):
    if is_block_size_4k() and rio_bs < Size.from_KiB(4):
        pytest.skip("Sub-4K I/O not supported in 4K block mode")
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
    if is_block_size_4k() and rio_bs < Size.from_KiB(4):
        pytest.skip("Sub-4K I/O not supported in 4K block mode")
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


@pytest.mark.parametrize("cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_64KiB])
@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB, CacheMode.WO])
def test_strict_engine_errors_concurrent(pyocf_ctx, cache_mode: CacheMode, cls: CacheLineSize):
    """Test that occupancy counter does not leak when concurrent sub-cacheline
    writes fail on the cache device. Uses two I/O queues (two threads) with
    sequential 4KiB writes to force concurrent requests onto the same cache line"""
    cache_vol_size = Size.from_MiB(50)
    ram_cache_volume = RamVolume(cache_vol_size)
    error_sectors = set(x for x in range(0, cache_vol_size, 512))
    error_device = ErrorDevice(ram_cache_volume, error_sectors, armed=False)
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(error_device, cache_mode=cache_mode, cache_line_size=cls)
    core = Core.using_device(core_device)

    # Two queues = two processing threads, enabling true concurrency.
    # With a single queue, invalidation runs synchronously (kick_sync)
    # before the next request, preventing the waiter race.
    queue1 = cache.get_default_queue()
    queue2 = Queue(cache, "io-queue-2")

    cache.add_core(core)
    core_volume = CoreVolume(core)
    core_volume.open()

    error_device.reset_stats()
    error_device.arm()

    # Sequential 4KiB writes from two jobs to the same address range.
    # Both jobs write to the same cache lines, so requests from different
    # queue threads contend on the same cache line locks.
    rio_bs = Size.from_KiB(4)
    rio_size = Size.from_MiB(1)

    (
        Rio()
        .target(core_volume)
        .njobs(2)
        .readwrite(ReadWrite.WRITE)
        .size(rio_size)
        .bs(rio_bs)
        .qd(16)
        .continue_on_error()
        .run([queue1, queue2])
    )

    cache.settle()

    assert cache.get_stats()["usage"]["occupancy"]["value"] == 0

    error_device.disarm()


@pytest.mark.parametrize("cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_64KiB])
@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB, CacheMode.WO])
def test_strict_engine_errors_partial(pyocf_ctx, cache_mode: CacheMode, cls: CacheLineSize):
    """Test that occupancy counter is correct when concurrent requests access
    the same cache line and only some fail. The error device injects a limited
    number of errors, so early cache writes fail (triggering invalidation)
    while later writes to the same cache lines succeed."""
    cache_vol_size = Size.from_MiB(50)
    ram_cache_volume = RamVolume(cache_vol_size)
    error_sectors = set(x for x in range(0, cache_vol_size, 512))
    error_device = ErrorDevice(
        ram_cache_volume, error_sectors, error_max_count=64, armed=False
    )
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(
        error_device, cache_mode=cache_mode, cache_line_size=cls
    )
    core = Core.using_device(core_device)

    queue1 = cache.get_default_queue()
    queue2 = Queue(cache, "io-queue-2")

    cache.add_core(core)
    core_volume = CoreVolume(core)
    core_volume.open()

    error_device.reset_stats()
    error_device.arm()

    rio_bs = Size.from_KiB(4)
    rio_size = Size.from_MiB(1)

    (
        Rio()
        .target(core_volume)
        .njobs(2)
        .readwrite(ReadWrite.WRITE)
        .size(rio_size)
        .bs(rio_bs)
        .qd(16)
        .continue_on_error()
        .run([queue1, queue2])
    )

    cache.settle()

    stats = cache.get_stats()
    occupancy_after_partial = stats["usage"]["occupancy"]["value"]
    cache_errors = stats["errors"]["cache_volume_wr"]["value"]

    # Some errors must have been injected, and some writes must have
    # succeeded (populating cache lines)
    assert cache_errors > 0
    assert occupancy_after_partial > 0

    # Now do all-error I/O to invalidate remaining cache lines.
    # Remove the error cap so every write fails.
    error_device.error_max_count = -1

    (
        Rio()
        .target(core_volume)
        .njobs(2)
        .readwrite(ReadWrite.WRITE)
        .size(rio_size)
        .bs(rio_bs)
        .qd(16)
        .continue_on_error()
        .run([queue1, queue2])
    )

    cache.settle()

    # All cache lines should be invalidated. If the occupancy counter
    # leaked during partial-error I/O, it won't reach zero.
    assert cache.get_stats()["usage"]["occupancy"]["value"] == 0

    error_device.disarm()
