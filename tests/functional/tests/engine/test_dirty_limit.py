#
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest

from pyocf.rio import Rio, ReadWrite
from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.io import IoDir
from pyocf.types.shared import CacheLineSize, SeqCutOffPolicy
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.time import advance_time_ms
from pyocf.utils import Size


@pytest.mark.parametrize("limit", [1, 1234, 0xFFFFFFFF, 0])
def test_dirty_limit_get_set(pyocf_ctx, limit):
    cache = Cache.start_on_device(RamVolume(Size.from_MiB(50)), cache_mode=CacheMode.WB)
    assert cache.get_dirty_limit() == 0, "no limit by default"
    cache.set_dirty_limit(limit)
    assert cache.get_dirty_limit() == limit


@pytest.mark.parametrize("limit", [1, 1234, 0xFFFFFFFF])
def test_dirty_limit_persistent(pyocf_ctx, limit):
    cache_device = RamVolume(Size.from_MiB(50))
    cache = Cache.start_on_device(cache_device, cache_mode=CacheMode.WB)
    cache.set_dirty_limit(limit)
    cache.stop()

    cache = Cache.load_from_device(cache_device, open_cores=False)
    assert cache.get_dirty_limit() == limit, "limit restored from metadata"


@pytest.mark.parametrize("limit", [2, 16, 128])
@pytest.mark.parametrize("mode", [m for m in CacheMode if m.lazy_write()])
@pytest.mark.parametrize("cls", CacheLineSize)
def test_dirty_limit_lazy_write(pyocf_ctx, cls, mode, limit):
    """
    Writes to new lines are written back up to the limit and written through
    above it; rewrites of dirty lines are still written back, also when their
    lines are hit by the fast path.
    """
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))
    cache = Cache.start_on_device(cache_device, cache_line_size=cls, cache_mode=mode)
    core = Core.using_device(core_device)
    cache.add_core(core)
    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)
    vol = CoreVolume(core)
    queue = cache.get_default_queue()
    cache.set_dirty_limit(limit)

    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(cls))
        .size(Size(limit * cls))
        .run([queue])
    )
    assert int(cache.get_stats()["conf"]["dirty"]) == limit
    assert core_device.get_stats()[IoDir.WRITE] == 0, "written back up to the limit"

    advance_time_ms(1)
    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(cls))
        .offset(Size(limit * cls))
        .size(Size(limit * cls))
        .run([queue])
    )
    assert int(cache.get_stats()["conf"]["dirty"]) == limit, "dirty lines stop at the limit"
    assert core_device.get_stats()[IoDir.WRITE] == limit, "lines over the limit written through"
    core_device.reset_stats()

    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(cls))
        .size(Size(cls))
        .run([queue])
    )
    assert core_device.get_stats()[IoDir.WRITE] == 0, "rewrite of a dirty line written back"
    assert int(cache.get_stats()["conf"]["dirty"]) == limit

    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(cls))
        .offset(Size((2 * limit - 1) * cls))
        .size(Size(cls))
        .run([queue])
    )
    assert core_device.get_stats()[IoDir.WRITE] == 1, "full hit to a clean line written through"
    assert int(cache.get_stats()["conf"]["dirty"]) == limit

    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(2 * cls))
        .offset(Size((limit - 1) * cls))
        .size(Size(2 * cls))
        .run([queue])
    )
    assert core_device.get_stats()[IoDir.WRITE] == 2, "request adding a dirty line written through"
    # The written through dirty line becomes clean after the request completes
    cache.settle()
    assert (
        int(cache.get_stats()["conf"]["dirty"]) == limit - 1
    ), "written through dirty line becomes clean"

    advance_time_ms(1)
    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(cls))
        .offset(Size((limit - 1) * cls))
        .size(Size(cls))
        .run([queue])
    )
    assert core_device.get_stats()[IoDir.WRITE] == 2, "below the limit written back again"
    assert int(cache.get_stats()["conf"]["dirty"]) == limit

    cache.flush()
    assert int(cache.get_stats()["conf"]["dirty"]) == 0
    core_device.reset_stats()

    advance_time_ms(1)
    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(cls))
        .offset(Size(limit * cls))
        .size(Size(limit * cls))
        .run([queue])
    )
    assert core_device.get_stats()[IoDir.WRITE] == 0, "after flush written back up to the limit"
    assert int(cache.get_stats()["conf"]["dirty"]) == limit

    # md5() of the exported object closes it - last
    cache.flush()
    assert core_device.md5() == vol.md5()


@pytest.mark.parametrize("limit", [2, 16, 128])
@pytest.mark.parametrize("mode", [m for m in CacheMode if m.lazy_write()])
@pytest.mark.parametrize("cls", CacheLineSize)
def test_dirty_limit_request_size(pyocf_ctx, cls, mode, limit):
    """
    A request is written back only if the cache lines it makes dirty fit under
    the limit; cache lines that are dirty already do not count.
    """
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))
    cache = Cache.start_on_device(cache_device, cache_line_size=cls, cache_mode=mode)
    core = Core.using_device(core_device)
    cache.add_core(core)
    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)
    vol = CoreVolume(core)
    queue = cache.get_default_queue()
    cache.set_dirty_limit(limit)

    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(cls))
        .size(Size((limit - 1) * cls))
        .run([queue])
    )
    assert int(cache.get_stats()["conf"]["dirty"]) == limit - 1
    assert core_device.get_stats()[IoDir.WRITE] == 0

    advance_time_ms(1)
    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(2 * cls))
        .offset(Size(limit * cls))
        .size(Size(2 * cls))
        .run([queue])
    )
    assert core_device.get_stats()[IoDir.WRITE] == 1, "request crossing the limit written through"
    assert int(cache.get_stats()["conf"]["dirty"]) == limit - 1

    # The new dirty line is dirty only in its first half
    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(cls + cls // 2))
        .offset(Size((limit - 2) * cls))
        .size(Size(cls + cls // 2))
        .run([queue])
    )
    assert core_device.get_stats()[IoDir.WRITE] == 1, "one new dirty line fits under the limit"
    assert int(cache.get_stats()["conf"]["dirty"]) == limit

    advance_time_ms(1)
    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(cls // 2))
        .offset(Size((limit - 1) * cls + cls // 2))
        .size(Size(cls // 2))
        .run([queue])
    )
    assert core_device.get_stats()[IoDir.WRITE] == 1, "write to a partly dirty line written back"
    assert int(cache.get_stats()["conf"]["dirty"]) == limit

    cache.flush()
    assert int(cache.get_stats()["conf"]["dirty"]) == 0
    core_device.reset_stats()

    advance_time_ms(1)
    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size((limit + 1) * cls))
        .size(Size((limit + 1) * cls))
        .run([queue])
    )
    assert (
        core_device.get_stats()[IoDir.WRITE] == 1
    ), "request larger than the limit written through"
    assert int(cache.get_stats()["conf"]["dirty"]) == 0

    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(limit * cls))
        .size(Size(limit * cls))
        .run([queue])
    )
    assert core_device.get_stats()[IoDir.WRITE] == 1, "request of the limit size written back"
    assert int(cache.get_stats()["conf"]["dirty"]) == limit

    # md5() of the exported object closes it - last
    cache.flush()
    assert core_device.md5() == vol.md5()


@pytest.mark.parametrize("limit", [2, 16, 128])
@pytest.mark.parametrize("cls", CacheLineSize)
def test_dirty_limit_disabled(pyocf_ctx, cls, limit):
    """With the limit set back to 0 writes are written back without a limit"""
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))
    cache = Cache.start_on_device(cache_device, cache_line_size=cls, cache_mode=CacheMode.WB)
    core = Core.using_device(core_device)
    cache.add_core(core)
    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)
    vol = CoreVolume(core)
    queue = cache.get_default_queue()
    cache.set_dirty_limit(limit)
    cache.set_dirty_limit(0)

    (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.WRITE)
        .bs(Size(cls))
        .size(Size((limit + 1) * cls))
        .run([queue])
    )
    assert core_device.get_stats()[IoDir.WRITE] == 0
    assert int(cache.get_stats()["conf"]["dirty"]) == limit + 1

    cache.flush()
    assert core_device.md5() == vol.md5()
