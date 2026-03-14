#
# Copyright(c) 2019-2022 Intel Corporation
# Copyright(c) 2024-2025 Huawei Technologies
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

import logging
import time
from math import ceil, isclose
from ctypes import c_int

import pytest

from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import IoDir, Sync
from pyocf.types.shared import OcfCompletion, CacheLineSize, SeqCutOffPolicy, CacheLines
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("mode", [CacheMode.WT])
def test_eviction_two_cores(pyocf_ctx, mode: CacheMode, cls: CacheLineSize):
    """Test if eviction works correctly when remapping cachelines between distinct cores."""
    cache_device = RamVolume(Size.from_MiB(50))

    core_device1 = RamVolume(Size.from_MiB(40))
    core_device2 = RamVolume(Size.from_MiB(40))
    cache = Cache.start_on_device(cache_device, cache_mode=mode, cache_line_size=cls)
    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)
    cache_size = cache.get_stats()["conf"]["size"]
    core1 = Core.using_device(core_device1, name="core1")
    core2 = Core.using_device(core_device2, name="core2")
    cache.add_core(core1)
    vol1 = CoreVolume(core1)
    cache.add_core(core2)
    vol2 = CoreVolume(core2)

    valid_io_size = Size.from_B(cache_size.B)
    test_data = Data(valid_io_size)
    send_io(vol1, test_data)
    send_io(vol2, test_data)

    cache.settle()

    stats1 = core1.get_stats()
    stats2 = core2.get_stats()
    # IO to the second core should evict all the data from the first core
    assert stats1["usage"]["occupancy"]["value"] == 0
    assert stats2["usage"]["occupancy"]["value"] == valid_io_size.blocks_4k


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("mode", [CacheMode.WT, CacheMode.WB, CacheMode.WO])
def test_write_size_greater_than_cache(pyocf_ctx, mode: CacheMode, cls: CacheLineSize):
    """Test if eviction does not occur when IO greater than cache size is submitted."""
    cache_device = RamVolume(Size.from_MiB(50))

    core_device = RamVolume(Size.from_MiB(200))
    cache = Cache.start_on_device(cache_device, cache_mode=mode, cache_line_size=cls)
    cache_size = cache.get_stats()["conf"]["size"]
    core = Core.using_device(core_device)
    cache.add_core(core)
    vol = CoreVolume(core)
    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    valid_io_size = Size.from_B(cache_size.B // 2)
    test_data = Data(valid_io_size)
    send_io(vol, test_data)

    stats = core.cache.get_stats()
    first_block_sts = stats["block"]
    first_usage_sts = stats["usage"]
    pt_writes_first = stats["req"]["wr_pt"]
    assert stats["usage"]["occupancy"]["value"] == (
        valid_io_size.B / Size.from_KiB(4).B
    ), "Occupancy after first IO"
    prev_writes_to_core = stats["block"]["core_volume_wr"]["value"]

    # Anything below 200 MiB is a valid size (less than core device size)
    # Writing over cache size (to the offset above first io) in this case should go
    # directly to core and shouldn't trigger eviction
    io_size_bigger_than_cache = Size.from_MiB(100)
    io_offset = valid_io_size
    test_data = Data(io_size_bigger_than_cache)
    send_io(vol, test_data, io_offset)

    if mode is not CacheMode.WT:
        # Flush first write
        cache.flush()
    stats = core.cache.get_stats()
    second_block_sts = stats["block"]
    second_usage_sts = stats["usage"]
    pt_writes_second = stats["req"]["wr_pt"]

    # Second write shouldn't affect cache and should go directly to core.
    # Cache occupancy shouldn't change
    # Second IO should go in PT
    assert first_usage_sts["occupancy"] == second_usage_sts["occupancy"]
    assert pt_writes_first["value"] == 0
    assert pt_writes_second["value"] == 1
    assert second_block_sts["cache_volume_wr"]["value"] == valid_io_size.blocks_4k
    assert (
        second_block_sts["core_volume_wr"]["value"]
        == valid_io_size.blocks_4k + io_size_bigger_than_cache.blocks_4k
    )


@pytest.mark.parametrize("io_dir", IoDir)
@pytest.mark.parametrize(
    "cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_16KiB, CacheLineSize.LINE_64KiB]
)
@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB])
def test_eviction_priority_1(pyocf_ctx, cls: CacheLineSize, cache_mode: CacheMode, io_dir: IoDir):
    """Verify if data of higher priority is not evicted by low priority data"""
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(200))
    cache = Cache.start_on_device(cache_device, cache_mode=cache_mode, cache_line_size=cls)
    core = Core.using_device(core_device)
    cache.add_core(core)
    vol = CoreVolume(core)

    high_prio_ioclass = 1
    low_prio_ioclass = 2

    cache.configure_partition(
        part_id=high_prio_ioclass,
        name="high_prio",
        max_size=100,
        priority=1,
    )
    cache.configure_partition(
        part_id=low_prio_ioclass,
        name="low_prio",
        max_size=100,
        priority=2,
    )

    def get_ioclass_occupancy(cache, ioclass_id):
        return cache.get_ioclass_stats(ioclass_id)["usage"]["occupancy"]["value"]

    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    cache_size_4k = cache.get_stats()["conf"]["size"].blocks_4k
    cache_line_size_4k = Size(cls).blocks_4k

    data = Data(4096)

    # Populate cache with high priority data
    for i in range(cache_size_4k):
        send_io(vol, data, i * 4096, high_prio_ioclass, io_dir)

    high_prio_ioclass_occupancy = get_ioclass_occupancy(cache, high_prio_ioclass)

    assert isclose(
        high_prio_ioclass_occupancy, cache_size_4k, abs_tol=cache_line_size_4k
    ), "High priority data should occupy the whole cache"

    # Write data of lower priority
    for i in range(cache_size_4k, 2 * cache_size_4k):
        send_io(vol, data, i * 4096, low_prio_ioclass, io_dir)

    high_prio_ioclass_occupancy = get_ioclass_occupancy(cache, high_prio_ioclass)
    low_prio_ioclass_occupancy = get_ioclass_occupancy(cache, low_prio_ioclass)

    assert isclose(
        high_prio_ioclass_occupancy, cache_size_4k, abs_tol=cache_line_size_4k
    ), "High priority data shouldn't be evicted"

    assert low_prio_ioclass_occupancy == 0


@pytest.mark.parametrize(
    ("cache_mode", "io_dir"),
    [
        (CacheMode.WB, IoDir.READ),
        (CacheMode.WT, IoDir.WRITE),
        (CacheMode.WT, IoDir.READ),
    ],
)
@pytest.mark.parametrize("cls", [CacheLineSize.LINE_16KiB, CacheLineSize.LINE_64KiB])
def test_eviction_priority_2(pyocf_ctx, cls: CacheLineSize, cache_mode: CacheMode, io_dir: IoDir):
    """Verify if data of low priority gets evicted by high priority data"""
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(200))
    cache = Cache.start_on_device(cache_device, cache_mode=cache_mode, cache_line_size=cls)
    core = Core.using_device(core_device)
    cache.add_core(core)
    vol = CoreVolume(core)

    high_prio_ioclass = 1
    low_prio_ioclass = 2

    cache.configure_partition(
        part_id=high_prio_ioclass,
        name="high_prio",
        max_size=100,
        priority=1,
    )
    cache.configure_partition(
        part_id=low_prio_ioclass,
        name="low_prio",
        max_size=100,
        priority=2,
    )

    def get_ioclass_occupancy(cache, ioclass_id):
        return cache.get_ioclass_stats(ioclass_id)["usage"]["occupancy"]["value"]

    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    cache_size_4k = cache.get_stats()["conf"]["size"].blocks_4k
    cache_line_size_4k = Size(cls).blocks_4k

    data = Data(4096)

    # Populate cache with low priority data
    for i in range(cache_size_4k):
        send_io(vol, data, i * 4096, low_prio_ioclass, io_dir)

    low_prio_ioclass_occupancy = get_ioclass_occupancy(cache, low_prio_ioclass)

    assert isclose(
        low_prio_ioclass_occupancy, cache_size_4k, abs_tol=cache_line_size_4k
    ), "Low priority data should occupy the whole cache"

    # Write data of higher priority
    for i in range(cache_size_4k, 2 * cache_size_4k):
        send_io(vol, data, i * 4096, high_prio_ioclass, io_dir)

    high_prio_ioclass_occupancy = get_ioclass_occupancy(cache, high_prio_ioclass)
    low_prio_ioclass_occupancy = get_ioclass_occupancy(cache, low_prio_ioclass)

    assert low_prio_ioclass_occupancy == 0, "Low priority data should be evicted from cache"

    assert isclose(
        high_prio_ioclass_occupancy, cache_size_4k, abs_tol=cache_line_size_4k
    ), "High priority data should occupy the whole cache"


@pytest.mark.parametrize("io_dir", IoDir)
@pytest.mark.parametrize("cls", [CacheLineSize.LINE_16KiB, CacheLineSize.LINE_64KiB])
@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB])
def test_eviction_freelist(pyocf_ctx, cls: CacheLineSize, cache_mode: CacheMode, io_dir: IoDir):
    """Verify that no eviction from low priority ioclass occurs if free cachelines are avaliable"""
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(200))
    cache = Cache.start_on_device(cache_device, cache_mode=cache_mode, cache_line_size=cls)
    core = Core.using_device(core_device)
    cache.add_core(core)
    vol = CoreVolume(core)

    high_prio_ioclass = 1
    low_prio_ioclasses = list(range(2, 33))

    cache.configure_partition(
        part_id=high_prio_ioclass,
        name="high_prio",
        max_size=100,
        priority=1,
    )
    for low_prio_ioclass in low_prio_ioclasses:
        cache.configure_partition(
            part_id=low_prio_ioclass,
            name=f"low_prio_{low_prio_ioclass}",
            max_size=100,
            priority=low_prio_ioclass * 5,
        )

    def get_ioclass_occupancy(cache, ioclass_id):
        return cache.get_ioclass_stats(ioclass_id)["usage"]["occupancy"]["value"]

    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    cache_size_4k = cache.get_stats()["conf"]["size"].blocks_4k
    cache_line_size_4k = Size(cls).blocks_4k

    cache_lines_written = 5
    data = Data(4096 * cache_line_size_4k)
    expected_occpancy_4k = (cache_lines_written * data.size) / 4096

    for i, ioclass in enumerate([high_prio_ioclass] + low_prio_ioclasses):
        for j in range(cache_lines_written):
            addr = (cache_lines_written * i + j) * data.size
            send_io(vol, data, addr, ioclass, io_dir)
            cache.settle()
        assert (
            get_ioclass_occupancy(cache, ioclass) == expected_occpancy_4k
        ), f"Doesn't match for ioclass {ioclass}"

    for ioclass in [high_prio_ioclass] + low_prio_ioclasses:
        assert (
            get_ioclass_occupancy(cache, ioclass) == expected_occpancy_4k
        ), f"Doesn't match for ioclass {ioclass}"

    while cache.get_stats()["usage"]["free"]["value"] > 0:
        addr += data.size
        send_io(vol, data, addr, high_prio_ioclass, io_dir)
        cache.settle()

    cache.settle()
    time.sleep(1)

    assert cache.get_stats()["usage"]["occupancy"]["value"] == cache_size_4k

    for ioclass in low_prio_ioclasses:
        assert (
            get_ioclass_occupancy(cache, ioclass) == expected_occpancy_4k
        ), f"Doesn't match for ioclass {ioclass}"


@pytest.mark.parametrize("cls", CacheLineSize)
def test_evict_overflown_pinned(pyocf_ctx, cls: CacheLineSize):
    """ Verify if overflown pinned ioclass is evicted """
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(100))
    cache = Cache.start_on_device(cache_device, cache_mode=CacheMode.WT, cache_line_size=cls)
    core = Core.using_device(core_device)
    cache.add_core(core)
    vol = CoreVolume(core)

    test_ioclass_id = 1
    pinned_ioclass_id = 2
    pinned_ioclass_max_occupancy = 10

    cache.configure_partition(
        part_id=test_ioclass_id, name="default_ioclass", max_size=100, priority=1,
    )
    cache.configure_partition(
        part_id=pinned_ioclass_id,
        name="pinned_ioclass",
        max_size=pinned_ioclass_max_occupancy,
        priority=-1,
    )

    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    cache_size = cache.get_stats()["conf"]["size"]

    data = Data(4096)

    # Populate cache with data
    for i in range(cache_size.blocks_4k):
        send_io(vol, data, i * 4096, test_ioclass_id)

    part_current_size = CacheLines(
        cache.get_partition_info(part_id=test_ioclass_id)["_curr_size"], cls
    )
    assert isclose(
        part_current_size.blocks_4k, cache_size.blocks_4k, abs_tol=Size(cls).blocks_4k
    ), "Failed to populate the default partition"

    # Repart - force overflow of second partition occupancy limit
    pinned_double_size = ceil((cache_size.blocks_4k * pinned_ioclass_max_occupancy * 2) / 100)
    for i in range(pinned_double_size):
        send_io(vol, data, i * 4096, pinned_ioclass_id)

    part_current_size = CacheLines(
        cache.get_partition_info(part_id=pinned_ioclass_id)["_curr_size"], cls
    )
    assert isclose(
        part_current_size.blocks_4k, pinned_double_size, abs_tol=Size(cls).blocks_4k
    ), "Occupancy of pinned ioclass doesn't match expected value"

    # Trigger IO to the default ioclass - force eviction from overlown ioclass
    for i in range(cache_size.blocks_4k):
        send_io(vol, data, (cache_size.blocks_4k + i) * 4096, test_ioclass_id)

    part_current_size = CacheLines(
        cache.get_partition_info(part_id=pinned_ioclass_id)["_curr_size"], cls
    )
    assert isclose(
        part_current_size.blocks_4k,
        ceil(cache_size.blocks_4k * 0.1),
        abs_tol=Size(cls).blocks_4k,
    ), "Overflown part has not been evicted"


@pytest.mark.parametrize(
    "cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_16KiB, CacheLineSize.LINE_64KiB]
)
def test_eviction_retry_stale_cline_count(pyocf_ctx, cls: CacheLineSize):
    """Regression test: eviction retry must account for lines already remapped.

    The eviction retry loop in ocf_evict_user_partitions() calls
    ocf_evict_user_partitions_once() up to EVICT_RETRY(2) times. A bug
    caused the retry to pass the original (stale) evict_cline_no instead
    of subtracting the lines already remapped in the first iteration.
    This led to ocf_lru_req_clines() being called with cline_no >
    ocf_engine_unmapped_count(req), triggering an assertion failure.

    The scenario requires:
    - Two low-priority partitions: one with a small positive eviction
      counter residual (part_a), one with counter=0 (part_b).
    - part_b gets counter=0 by being populated via repartitioning
      (not eviction), so it never participates in counter updates.
    - A single multi-cacheline write triggers eviction where:
      1st pass: part_b skipped (counter=0), part_a fully evicted
        (counter→<=0). Partial eviction. no_more_counters=true.
      2nd pass (retry): counter update replenishes part_b. With the
        bug, stale evict_cline_no causes to_evict > unmapped_count.
    """
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(200))
    cache = Cache.start_on_device(
        cache_device, cache_mode=CacheMode.WT, cache_line_size=cls,
    )
    core = Core.using_device(core_device)
    cache.add_core(core)
    vol = CoreVolume(core)
    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    target_ioclass = 1
    part_a_ioclass = 2
    part_b_ioclass = 3

    cache.configure_partition(
        part_id=target_ioclass, name="target", max_size=100, priority=1,
    )
    cache.configure_partition(
        part_id=part_a_ioclass, name="part_a", max_size=100, priority=2,
    )
    cache.configure_partition(
        part_id=part_b_ioclass, name="part_b", max_size=100, priority=3,
    )

    cl_4k = Size(cls).blocks_4k
    cache_lines = cache.get_stats()["conf"]["size"].blocks_4k // cl_4k
    cl_bytes = int(Size(cls))

    def get_occupancy(ioclass_id):
        return (
            cache.get_ioclass_stats(ioclass_id)["usage"]["occupancy"]["value"]
            // cl_4k
        )

    # Phase 1: Fill cache entirely with part_a data.
    data = Data(cl_bytes)
    for i in range(cache_lines):
        send_io(vol, data, i * cl_bytes, part_a_ioclass)

    cache.settle()
    assert get_occupancy(part_a_ioclass) == cache_lines

    # Phase 2: Write to target partition to trigger first eviction cycle
    # and establish counter state.
    #
    # During the first eviction cycle the eviction counters are
    # initialized (counter_a = min(cache_lines, 256)). We evict
    # (counter - 6) lines to leave a small positive residual
    # counter_a = 6. counter_b stays at 0 since part_b is empty.
    counter_initial = min(cache_lines, 256)
    first_evict = counter_initial - 6

    evict_data = Data(first_evict * cl_bytes)
    evict_addr = cache_lines * cl_bytes
    send_io(vol, evict_data, evict_addr, target_ioclass)

    cache.settle()
    assert get_occupancy(target_ioclass) == first_evict
    a_remaining = get_occupancy(part_a_ioclass)

    # Phase 3: Repartition data from part_a to part_b.
    #
    # Reading cached part_a data with part_b's ioclass causes
    # cache-hit repartitioning (A → B) without touching eviction
    # counters. After this, part_b has data but counter_b is
    # still 0.
    #
    # Read from the high end of the address range (most recently
    # used, guaranteed to still be cached). Use individual
    # cache-line reads so that any evicted addresses simply go
    # pass-through without disturbing the test.
    a_keep = min(a_remaining, counter_initial - 2)
    repart_count = a_remaining - a_keep
    for i in range(repart_count):
        addr = (cache_lines - 1 - i) * cl_bytes
        send_io(vol, data, addr, part_b_ioclass, IoDir.READ)

    cache.settle()
    actual_a = get_occupancy(part_a_ioclass)
    actual_b = get_occupancy(part_b_ioclass)

    # Phase 4: Trigger the bug.
    #
    # Issue a single multi-cacheline write to target. The request
    # needs trigger_count unmapped cache lines. In eviction:
    #
    #   1st pass of ocf_evict_user_partitions_once():
    #     - part_b (prio 3): counter=0 → SKIPPED
    #     - part_a (prio 2): counter≈6, evicts all ~a_keep lines,
    #       counter→<=0
    #     - partial eviction, no_more_counters=true
    #
    #   Counter update: replenishes part_b counter.
    #
    #   2nd pass (retry):
    #     - BUG: to_evict=trigger_count > unmapped (trigger_count - a_keep)
    #     - FIX: to_evict=trigger_count - a_keep == unmapped → OK
    #
    # trigger_count must be > actual_a (so part_a can't satisfy it
    # alone) and <= actual_b (so part_b can in the retry).
    trigger_count = actual_a + actual_b
    trigger_data = Data(trigger_count * cl_bytes)
    trigger_addr = (cache_lines + first_evict) * cl_bytes
    send_io(vol, trigger_data, trigger_addr, target_ioclass)

    # If we get here without an assertion failure, the fix works.
    cache.settle()
    assert get_occupancy(target_ioclass) == first_evict + trigger_count


def send_io(
    vol: CoreVolume, data: Data, addr: int = 0, target_ioclass: int = 0, io_dir: IoDir = IoDir.WRITE
):
    vol.open()
    io = vol.new_io(
        vol.parent.get_default_queue(),
        addr,
        data.size,
        io_dir,
        target_ioclass,
        0,
    )

    io.set_data(data)

    completion = Sync(io).submit()
    vol.close()

    assert completion.results["err"] == 0, "IO to exported object completion"
