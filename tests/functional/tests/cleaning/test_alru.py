#
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest

from pyocf.time import advance_time, advance_time_ms, reset_time
from pyocf.types.cache import (
    Cache,
    CacheMode,
    CleaningPolicy,
    AlruParams,
)
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.types.shared import CacheLineSize
from pyocf.utils import Size
from pyocf.rio import Rio, ReadWrite


STATS_BLOCK_SIZE = Size.from_KiB(4)


def dirty_blocks(stats):
    return stats["usage"]["dirty"]["value"]


def cleaner_req(stats):
    return stats["req"]["cleaner"]["value"]


def cleaner_cache_rd(stats):
    return stats["block"]["cleaner_cache_rd"]["value"]


def cleaner_core_wr(stats):
    return stats["block"]["cleaner_core_wr"]["value"]


# -- cache setup helpers --

def setup_cache(pyocf_ctx, cls=CacheLineSize.DEFAULT):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(100))

    cache = Cache.start_on_device(
        cache_device, cache_mode=CacheMode.WB,
        cache_line_size=cls, metadata_volatile=True,
    )
    core = Core.using_device(core_device)
    cache.add_core(core)

    cache.set_cleaning_policy(CleaningPolicy.NOP)

    vol = CoreVolume(core)
    queue = cache.get_default_queue()

    return cache, core, vol, queue


def fill_dirty(vol, queue, offset, size):
    Rio().target(vol).bs(Size.from_KiB(4)).size(size).offset(offset) \
        .readwrite(ReadWrite.WRITE).run([queue])


# -- tests --

@pytest.mark.parametrize("wake_up", [0, 1, 5, 20, 100])
def test_alru_wake_up_time(pyocf_ctx, manual_cleaner, wake_up):
    """Verify wake_up_time is propagated as the interval to the cleaner
    completion callback when no flush was performed."""
    cache, core, vol, queue = setup_cache(pyocf_ctx)

    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.WAKE_UP_TIME, wake_up
    )
    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.ACTIVITY_THRESHOLD, 0
    )
    cache.set_cleaning_policy(CleaningPolicy.ALRU)

    # No dirty data — cleaner has nothing to do.
    # advance past clean_later check
    advance_time(wake_up + 1)

    manual_cleaner.run(cache)

    assert manual_cleaner.last_interval == wake_up * 1000


@pytest.mark.parametrize("stale_time", [3, 5, 10])
def test_alru_staleness_time(pyocf_ctx, manual_cleaner, stale_time):
    """Verify only data older than stale_buffer_time is cleaned."""
    cache, core, vol, queue = setup_cache(pyocf_ctx)

    # Enable ALRU before writes so each cache line gets its own per-write
    # timestamp via add_alru_head. (Switching from NOP would reset all
    # timestamps to a single "now" value for the existing dirty clines.)
    # wake_up_time=1: the cleaner's clean_later check enforces at least
    # 1 sec between back-to-back cleaner attempts. activity_threshold=200
    # is small enough never to interfere.
    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.WAKE_UP_TIME, 1
    )
    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.STALE_BUFFER_TIME, stale_time
    )
    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.ACTIVITY_THRESHOLD, 200
    )
    cache.set_cleaning_policy(CleaningPolicy.ALRU)

    half = Size.from_MiB(5)
    half_blocks = half // STATS_BLOCK_SIZE

    # Fill first half (timestamp == 0 sec)
    fill_dirty(vol, queue, Size(0), half)

    assert dirty_blocks(cache.get_stats()) == half_blocks

    # Advance 2.5 sec — crosses the activity threshold and moves the
    # clock two whole seconds forward so the second half gets a
    # distinct second-precision timestamp.
    advance_time_ms(2500)

    # Fill second half (timestamp == 2 sec)
    fill_dirty(vol, queue, half, half)

    assert dirty_blocks(cache.get_stats()) == half_blocks * 2

    # Advance to exactly stale_time seconds from T0. This is the
    # earliest point where compute_timestamp doesn't underflow (so
    # the cleaner makes a meaningful eligibility decision), while
    # keeping compute_timestamp == 0 — neither half eligible yet.
    advance_time_ms(stale_time * 1000 - 2500)

    # Cleaner runs but flushes nothing — both halves still inside
    # the staleness window.
    manual_cleaner.run_until_idle(cache)
    assert dirty_blocks(cache.get_stats()) == half_blocks * 2, \
        "No data should be flushed before staleness time is reached"

    # Advance another 2.5 sec → compute_timestamp == 2. First half
    # (ts=0) becomes eligible; second half (ts=2) does not. The
    # 2 sec gap also satisfies the wake_up_time clean_later check
    # after the previous cleaner attempt.
    advance_time_ms(2500)

    manual_cleaner.run_until_idle(cache)
    assert dirty_blocks(cache.get_stats()) == half_blocks

    # Advance another 2 sec so compute_timestamp == 4 and the second
    # half also becomes stale.
    advance_time(2)

    manual_cleaner.run_until_idle(cache)
    assert dirty_blocks(cache.get_stats()) == 0


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("flush_max", [1, 10, 100])
def test_alru_flush_max_buffers(pyocf_ctx, manual_cleaner, cls, flush_max):
    """Verify each cleaner iteration flushes at most flush_max_buffers
    cache lines."""
    cache, core, vol, queue = setup_cache(pyocf_ctx, cls=cls)

    io_size = Size.from_MiB(10)
    fill_dirty(vol, queue, Size(0), io_size)

    total_clines = io_size // Size(cls)
    blocks_per_cline = Size(cls) // STATS_BLOCK_SIZE

    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.WAKE_UP_TIME, 0
    )
    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.STALE_BUFFER_TIME, 1
    )
    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.ACTIVITY_THRESHOLD, 0
    )
    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.FLUSH_MAX_BUFFERS, flush_max
    )
    cache.set_cleaning_policy(CleaningPolicy.ALRU)

    advance_time(2)

    cleaned_clines = 0
    remaining = total_clines

    while remaining > 0:
        stats = cache.get_stats()
        prev_req = cleaner_req(stats)
        prev_rd = cleaner_cache_rd(stats)
        prev_wr = cleaner_core_wr(stats)

        manual_cleaner.run(cache)

        stats = cache.get_stats()
        batch = cleaner_req(stats) - prev_req
        rd_batch = cleaner_cache_rd(stats) - prev_rd
        wr_batch = cleaner_core_wr(stats) - prev_wr

        expected = min(flush_max, remaining)
        assert batch == expected, \
            f"Expected {expected} cache lines flushed, got {batch}"
        assert rd_batch == expected * blocks_per_cline, \
            f"Expected {expected * blocks_per_cline} cache read blocks, got {rd_batch}"
        assert wr_batch == expected * blocks_per_cline, \
            f"Expected {expected * blocks_per_cline} core write blocks, got {wr_batch}"

        remaining -= batch
        cleaned_clines += batch

    assert dirty_blocks(cache.get_stats()) == 0
    assert cleaned_clines == total_clines


@pytest.mark.parametrize("activity_threshold", [2000, 5000, 10000])
def test_alru_activity_threshold(pyocf_ctx, manual_cleaner, activity_threshold):
    """Verify cleaner does not run while I/O activity is recent, and starts
    cleaning once the activity threshold is exceeded."""
    cache, core, vol, queue = setup_cache(pyocf_ctx)

    io_size = Size.from_MiB(10)
    fill_dirty(vol, queue, Size(0), io_size)

    total_blocks = io_size // STATS_BLOCK_SIZE

    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.WAKE_UP_TIME, 1
    )
    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.STALE_BUFFER_TIME, 1
    )
    cache.set_cleaning_policy_param(
        CleaningPolicy.ALRU, AlruParams.ACTIVITY_THRESHOLD, activity_threshold
    )
    cache.set_cleaning_policy(CleaningPolicy.ALRU)

    # Advance past staleness (1 sec) but NOT past activity threshold.
    # All test values are >= 2000 ms, so 1500 ms is always inside the
    # activity window while still past the staleness boundary.
    advance_time_ms(1500)

    manual_cleaner.run(cache)

    assert dirty_blocks(cache.get_stats()) == total_blocks, \
        "Cleaner should not run while within activity threshold"

    # Now advance past the activity threshold
    advance_time_ms(activity_threshold)

    manual_cleaner.run_until_idle(cache)

    assert dirty_blocks(cache.get_stats()) == 0
