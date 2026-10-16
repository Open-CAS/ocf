#
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

import time
from threading import Thread

import pytest

from pyocf.types.cache import (
    Cache,
    CacheMode,
    CleaningPolicy,
    PrefetchPolicy,
    ReadaheadParams,
)
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import Io, IoDir
from pyocf.rio import ReadWrite, Rio
from pyocf.types.shared import CacheLineSize, OcfError, OcfErrorCode, SeqCutOffPolicy
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size

UNCLASSIFIED = 0
PREFETCH = 33
LINES = 128


def fill(vol, ioclass, first_line=0, rw=ReadWrite.WRITE):
    rio = (
        Rio()
        .target(vol)
        .bs(Size.from_KiB(4))
        .offset(Size.from_KiB(4 * first_line))
        .size(Size.from_KiB(4 * LINES))
        .readwrite(rw)
        .io_class(ioclass)
    )
    rio.run([vol.parent.get_default_queue()])

    assert rio.error_count == 0


def usage(cache, ioclass):
    stats = cache.get_ioclass_stats(ioclass)["usage"]
    return stats["occupancy"]["value"], stats["dirty"]["value"]


def prepare(cache_mode, core_device=None):
    cache_device = RamVolume(Size.from_MiB(50))
    if core_device is None:
        core_device = RamVolume(Size.from_MiB(50))
    cache = Cache.start_on_device(
        cache_device, cache_mode=cache_mode, cache_line_size=CacheLineSize.LINE_4KiB
    )
    core = Core.using_device(core_device)
    cache.add_core(core)
    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    return cache_device, cache, CoreVolume(core)


class HoldVolume(RamVolume):
    """RAM volume able to hold IOs in flight until released"""

    def __init__(self, size):
        super().__init__(size)
        self.hold = False
        self.held = []

    def do_forward_io(self, token, rw, addr, nbytes, offset):
        if self.hold:
            self.held.append((token, rw, addr, nbytes, offset))
        else:
            super().do_forward_io(token, rw, addr, nbytes, offset)

    def release(self, error=0):
        self.hold = False
        held, self.held = self.held, []
        for args in held:
            if error:
                Io.forward_end(args[0], error)
            else:
                super().do_forward_io(*args)


def wait_for(condition, timeout=10):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "Timed out waiting for condition"
        time.sleep(0.01)


def submit_async(vol, addr, io_dir, ioclass, results):
    io = vol.new_io(vol.parent.get_default_queue(), addr, 4096, io_dir, ioclass, 0)
    data = Data(4096)
    io.set_data(data)
    io.callback = lambda err: results.append(err)
    io.submit()
    # Keep IO and its data alive until completion
    return io, data


def configure_in_thread(func, timeout=10):
    """Run configuration in a thread to detect a deadlock instead of hanging"""
    errors = []

    def run():
        try:
            func()
        except Exception as e:  # noqa E722
            errors.append(e)

    thread = Thread(target=run)
    thread.start()
    thread.join(timeout)
    assert not thread.is_alive(), "IO class configuration deadlocked"
    assert not errors, errors


def check_totals(cache):
    """Occupancy and dirty of all IO classes must sum up to cache totals"""
    stats = cache.get_stats()["usage"]
    occupancy, dirty = 0, 0
    for ioclass in range(PREFETCH + 1):
        try:
            o, d = usage(cache, ioclass)
        except OcfError:
            continue
        assert o <= stats["occupancy"]["value"], f"IO class {ioclass} occupancy {o}"
        assert d <= stats["dirty"]["value"], f"IO class {ioclass} dirty {d}"
        occupancy += o
        dirty += d
    assert occupancy == stats["occupancy"]["value"]
    assert dirty == stats["dirty"]["value"]


@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB])
def test_ioclass_repart_update(pyocf_ctx, cache_mode):
    """
    Verify that cache lines of an updated IO class are moved to the unclassified
    IO class only if requested, that dirty data stays consistent and survives
    flush and cache load, and that lines get reclassified on next access.
    """
    cache_device, cache, vol = prepare(cache_mode)
    dirty = LINES if cache_mode == CacheMode.WB else 0

    cache.configure_partition(part_id=1, name="class1", max_size=100, priority=1)
    fill(vol, 1)
    assert usage(cache, 1) == (LINES, dirty)
    assert usage(cache, UNCLASSIFIED) == (0, 0)

    cache.configure_partition(part_id=1, name="class1_v2", max_size=100, priority=1)
    assert usage(cache, 1) == (LINES, dirty)
    assert usage(cache, UNCLASSIFIED) == (0, 0)

    cache.configure_partition(
        part_id=1, name="class1_v3", max_size=100, priority=1, repart=True
    )
    assert usage(cache, 1) == (0, 0)
    assert usage(cache, UNCLASSIFIED) == (LINES, dirty)

    # Hits reclassify lines back to the IO class of the request
    fill(vol, 1, rw=ReadWrite.READ)
    assert usage(cache, 1) == (LINES, dirty)
    assert usage(cache, UNCLASSIFIED) == (0, 0)

    cache.configure_partition(
        part_id=1, name="class1_v3", max_size=100, priority=1, repart=True
    )
    cache.flush()
    assert usage(cache, UNCLASSIFIED) == (LINES, 0)
    assert cache.get_stats()["usage"]["dirty"]["value"] == 0

    cache.stop()
    cache = Cache.load_from_device(cache_device)
    assert usage(cache, 1) == (0, 0)
    assert usage(cache, UNCLASSIFIED) == (LINES, 0)


@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB])
def test_ioclass_repart_remove(pyocf_ctx, cache_mode):
    """
    Verify that removing an IO class moves its cache lines to the unclassified
    IO class only if requested.
    """
    cache_device, cache, vol = prepare(cache_mode)
    dirty = LINES if cache_mode == CacheMode.WB else 0

    cache.configure_partition(part_id=1, name="class1", max_size=100, priority=1)
    cache.configure_partition(part_id=2, name="class2", max_size=100, priority=1)
    fill(vol, 1, first_line=0)
    fill(vol, 2, first_line=LINES)
    assert usage(cache, 1) == (LINES, dirty)
    assert usage(cache, 2) == (LINES, dirty)

    cache.remove_partition(1, repart=True)
    cache.remove_partition(2, repart=False)
    assert usage(cache, UNCLASSIFIED) == (LINES, dirty)

    # Re-added IO class 1 starts empty, IO class 2 keeps its old lines
    cache.configure_partition(part_id=1, name="class1", max_size=100, priority=1)
    cache.configure_partition(part_id=2, name="class2", max_size=100, priority=1)
    assert usage(cache, 1) == (0, 0)
    assert usage(cache, 2) == (LINES, dirty)
    assert usage(cache, UNCLASSIFIED) == (LINES, dirty)

    cache.flush()
    assert cache.get_stats()["usage"]["dirty"]["value"] == 0


@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB])
def test_ioclass_repart_inactive(pyocf_ctx, cache_mode):
    """
    Verify that repart of an already removed IO class still holding cache
    lines moves them to the unclassified IO class, and that repart of an
    empty IO class doesn't change anything.
    """
    cache_device, cache, vol = prepare(cache_mode)
    dirty = LINES if cache_mode == CacheMode.WB else 0

    cache.configure_partition(part_id=1, name="class1", max_size=100, priority=1)
    cache.configure_partition(part_id=2, name="class2", max_size=100, priority=1)
    fill(vol, 1, first_line=0)
    fill(vol, 2, first_line=LINES)

    # Removed IO class keeps its cache lines
    cache.remove_partition(1, repart=False)
    assert cache.get_stats()["usage"]["occupancy"]["value"] == 2 * LINES
    assert usage(cache, UNCLASSIFIED) == (0, 0)

    # Repart of the already removed IO class moves them
    cache.remove_partition(1, repart=True)
    assert usage(cache, UNCLASSIFIED) == (LINES, dirty)
    assert usage(cache, 2) == (LINES, dirty)
    check_totals(cache)

    # Repart of empty IO classes, both removed and active, changes nothing
    cache.configure_partition(part_id=3, name="class3", max_size=100, priority=1)
    cache.remove_partition(1, repart=True)
    cache.configure_partition(part_id=3, name="class3", max_size=100, priority=1, repart=True)
    cache.remove_partition(4, repart=True)
    assert usage(cache, UNCLASSIFIED) == (LINES, dirty)
    assert usage(cache, 2) == (LINES, dirty)
    assert usage(cache, 3) == (0, 0)
    check_totals(cache)

    # Re-added IO class 1 starts empty
    cache.configure_partition(part_id=1, name="class1", max_size=100, priority=1)
    assert usage(cache, 1) == (0, 0)

    cache.flush()
    assert cache.get_stats()["usage"]["dirty"]["value"] == 0


@pytest.mark.parametrize("ioclass", [UNCLASSIFIED, PREFETCH])
def test_ioclass_repart_default_ioclass(pyocf_ctx, ioclass):
    """
    Verify that the repart flag is ignored for the default IO classes, whose
    classification rules can't change.
    """
    cache_device, cache, vol = prepare(CacheMode.WT)

    cache.set_prefetch_policy(1 << PrefetchPolicy.READAHEAD)
    cache.set_prefetch_param(PrefetchPolicy.READAHEAD, ReadaheadParams.THRESHOLD, 0)

    # Sequential reads populate the unclassified IO class and trigger
    # readahead populating the prefetch IO class
    fill(vol, UNCLASSIFIED, rw=ReadWrite.READ)
    cache.settle()

    unclassified = usage(cache, UNCLASSIFIED)
    prefetch = usage(cache, PREFETCH)
    assert unclassified[0] > 0
    assert prefetch[0] > 0

    info = cache.get_partition_info(ioclass)
    cache.configure_partition(
        part_id=ioclass,
        name=info["_name"],
        max_size=info["_max_size"],
        priority=info["_priority"],
        cache_mode=info["_cache_mode"],
        repart=True,
    )

    assert usage(cache, UNCLASSIFIED) == unclassified
    assert usage(cache, PREFETCH) == prefetch


@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB])
def test_ioclass_repart_inflight_io(pyocf_ctx, cache_mode):
    """
    Verify that repartitioning moves cache lines held by in-flight requests,
    including lines mapped by a read miss that aren't valid yet, and that
    accounting and data stay consistent once the requests complete.
    """
    pyocf_ctx.register_volume_type(HoldVolume)
    core_device = HoldVolume(Size.from_MiB(10))
    cache_device, cache, vol = prepare(cache_mode, core_device)
    dirty = LINES if cache_mode == CacheMode.WB else 0

    cache.configure_partition(part_id=1, name="class1", max_size=100, priority=1)
    fill(vol, 1)

    # Read misses of IO class 1 get held on core read, with their cache lines
    # mapped to IO class 1, but not valid yet. In WT mode write hits get held
    # on core write as well.
    core_device.hold = True
    vol.open()
    results, ios = [], []
    for i in range(LINES, 2 * LINES):
        ios.append(submit_async(vol, i * 4096, IoDir.READ, 1, results))
    expected_held = LINES
    if cache_mode == CacheMode.WT:
        for i in range(LINES // 2):
            ios.append(submit_async(vol, i * 4096, IoDir.WRITE, 1, results))
        expected_held += LINES // 2
    wait_for(lambda: len(core_device.held) == expected_held)

    configure_in_thread(
        lambda: cache.configure_partition(
            part_id=1, name="class1", max_size=100, priority=1, repart=True
        )
    )

    core_device.release()
    wait_for(lambda: len(results) == len(ios))
    vol.close()
    cache.settle()
    assert results == [0] * len(ios)

    assert usage(cache, 1) == (0, 0)
    assert usage(cache, UNCLASSIFIED) == (2 * LINES, dirty)
    check_totals(cache)

    cache.flush()
    assert usage(cache, UNCLASSIFIED) == (2 * LINES, 0)
    check_totals(cache)

    cache.stop()
    cache = Cache.load_from_device(cache_device)
    assert usage(cache, 1) == (0, 0)
    assert usage(cache, UNCLASSIFIED) == (2 * LINES, 0)

    # Reading the whole exported object inserts it into the cache, so check
    # data as the last step
    vol = CoreVolume(cache.get_core_by_name("core"))
    assert core_device.md5() == vol.md5()


def test_ioclass_lazy_repart_invalid_line(pyocf_ctx):
    """
    Verify accounting when a request reclassifies a cache line that is mapped,
    but not valid: a read miss fails, leaving its cache line mapped for the
    request of another IO class waiting for it.
    """
    pyocf_ctx.register_volume_type(HoldVolume)
    core_device = HoldVolume(Size.from_MiB(10))
    cache_device, cache, vol = prepare(CacheMode.WT, core_device)

    cache.configure_partition(part_id=1, name="class1", max_size=100, priority=1)
    cache.configure_partition(part_id=2, name="class2", max_size=100, priority=1)

    core_device.hold = True
    vol.open()
    first, second, ios = [], [], []
    for i in range(LINES):
        ios.append(submit_async(vol, i * 4096, IoDir.READ, 1, first))
    wait_for(lambda: len(core_device.held) == LINES)

    # Requests of IO class 2 wait for the cache lines locked by IO class 1
    for i in range(LINES):
        ios.append(submit_async(vol, i * 4096, IoDir.READ, 2, second))
    time.sleep(0.5)
    assert len(second) == 0

    core_device.release(error=-OcfErrorCode.OCF_ERR_IO)
    wait_for(lambda: len(first) == LINES and len(second) == LINES)
    vol.close()
    cache.settle()
    assert all(err != 0 for err in first)
    assert second == [0] * LINES

    assert usage(cache, 1) == (0, 0)
    assert usage(cache, 2) == (LINES, 0)
    check_totals(cache)


def test_ioclass_repart_during_cleaning(pyocf_ctx):
    """
    Verify that repartitioning dirty cache lines that are being cleaned keeps
    dirty accounting consistent. Cleaning policy runs hold the cache
    management lock, so they can't overlap with IO class configuration, but
    cleaning triggered by eviction runs without it.
    """
    pyocf_ctx.register_volume_type(HoldVolume)
    core_device = HoldVolume(Size.from_MiB(20))
    cache_device, cache, vol = prepare(CacheMode.WB, core_device)
    cache.set_cleaning_policy(CleaningPolicy.NOP)
    cache_lines = cache.get_stats()["conf"]["size"].blocks_4k

    # Fill the whole cache with dirty data, so that eviction requires cleaning
    cache.configure_partition(part_id=1, name="class1", max_size=100, priority=1)
    rio = (
        Rio()
        .target(vol)
        .bs(Size.from_KiB(4))
        .size(Size.from_KiB(4 * cache_lines))
        .readwrite(ReadWrite.WRITE)
        .io_class(1)
    )
    rio.run([vol.parent.get_default_queue()])
    assert rio.error_count == 0
    assert usage(cache, 1) == (cache_lines, cache_lines)

    # Write a new block, triggering cleaning, held on core write
    core_device.hold = True
    vol.open()
    results = []
    io = submit_async(vol, cache_lines * 4096, IoDir.WRITE, 1, results)
    wait_for(lambda: len(core_device.held) > 0)
    time.sleep(0.5)

    configure_in_thread(
        lambda: cache.configure_partition(
            part_id=1, name="class1", max_size=100, priority=1, repart=True
        )
    )
    assert usage(cache, 1) == (0, 0)
    assert usage(cache, UNCLASSIFIED) == (cache_lines, cache_lines)

    core_device.release()
    wait_for(lambda: len(results) == 1)
    vol.close()
    cache.settle()
    assert results == [0]

    occupancy, dirty = usage(cache, UNCLASSIFIED)
    assert dirty < cache_lines, "Some cache lines should have been cleaned"
    assert usage(cache, 1)[1] == 0
    check_totals(cache)

    cache.flush()
    assert usage(cache, UNCLASSIFIED)[1] == 0
    check_totals(cache)
    assert core_device.md5() == vol.md5()


@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB])
def test_ioclass_repart_multiple_cores(pyocf_ctx, cache_mode):
    """
    Verify per core accounting of repartitioned cache lines, including removal
    of a core afterwards.
    """
    cache_device, cache, vol1 = prepare(cache_mode)
    core2 = Core.using_device(RamVolume(Size.from_MiB(50)), name="core2")
    cache.add_core(core2)
    vol2 = CoreVolume(core2)
    core1 = vol1.core
    dirty = LINES if cache_mode == CacheMode.WB else 0

    def core_usage(core, ioclass):
        stats = core.get_ioclass_stats(ioclass)["usage"]
        return stats["occupancy"]["value"], stats["dirty"]["value"]

    cache.configure_partition(part_id=1, name="class1", max_size=100, priority=1)
    fill(vol1, 1)
    fill(vol2, 1, first_line=LINES)
    fill(vol2, UNCLASSIFIED, first_line=2 * LINES)

    cache.configure_partition(
        part_id=1, name="class1", max_size=100, priority=1, repart=True
    )
    assert core_usage(core1, 1) == (0, 0)
    assert core_usage(core2, 1) == (0, 0)
    assert core_usage(core1, UNCLASSIFIED) == (LINES, dirty)
    assert core_usage(core2, UNCLASSIFIED) == (2 * LINES, 2 * dirty)
    check_totals(cache)

    cache.remove_core(core1)
    assert usage(cache, 1) == (0, 0)
    assert usage(cache, UNCLASSIFIED) == (2 * LINES, 2 * dirty)
    check_totals(cache)

    cache.flush()
    assert usage(cache, UNCLASSIFIED) == (2 * LINES, 0)
    check_totals(cache)


@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB])
def test_ioclass_repart_partial_lines(pyocf_ctx, cache_mode):
    """
    Verify repartitioning of partially valid and partially dirty cache lines.
    """
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))
    cache = Cache.start_on_device(
        cache_device, cache_mode=cache_mode, cache_line_size=CacheLineSize.LINE_64KiB
    )
    core = Core.using_device(core_device)
    cache.add_core(core)
    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)
    vol = CoreVolume(core)
    line = int(CacheLineSize.LINE_64KiB)
    blocks = line // 4096

    cache.configure_partition(part_id=1, name="class1", max_size=100, priority=1)

    # A single 4KiB block in each cache line, at varying positions
    vol.open()
    for i in range(LINES):
        vol.sync_io(
            vol.parent.get_default_queue(), i * line + (i % blocks) * 4096,
            Data(4096), IoDir.WRITE, io_class=1
        )
    vol.close()

    # Usage is accounted in whole cache lines
    full = LINES * blocks
    dirty = full if cache_mode == CacheMode.WB else 0
    before = usage(cache, 1)
    assert before == (full, dirty)

    cache.configure_partition(
        part_id=1, name="class1", max_size=100, priority=1, repart=True
    )
    assert usage(cache, 1) == (0, 0)
    assert usage(cache, UNCLASSIFIED) == before
    check_totals(cache)

    # Fill rest of the cache lines from IO class 1, getting them reclassified
    rio = (
        Rio()
        .target(vol)
        .bs(Size.from_KiB(4))
        .size(Size(LINES * line))
        .readwrite(ReadWrite.WRITE)
        .io_class(1)
    )
    rio.run([vol.parent.get_default_queue()])
    assert rio.error_count == 0
    assert usage(cache, 1) == (full, dirty)
    assert usage(cache, UNCLASSIFIED) == (0, 0)
    check_totals(cache)

    cache.flush()
    check_totals(cache)
    assert core_device.md5() == vol.md5()
