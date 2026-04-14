#
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest

from pyocf.types.cache import (
    Cache,
    CacheMode,
    CleaningPolicy,
    AcpParams,
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
def test_acp_wake_up_time(pyocf_ctx, manual_cleaner, wake_up):
    """Verify wake_up_time is propagated as the interval to the cleaner
    completion callback after a flush."""
    cache, core, vol, queue = setup_cache(pyocf_ctx)

    io_size = Size.from_MiB(1)
    fill_dirty(vol, queue, Size(0), io_size)

    cache.set_cleaning_policy_param(
        CleaningPolicy.ACP, AcpParams.WAKE_UP_TIME, wake_up
    )
    cache.set_cleaning_policy(CleaningPolicy.ACP)

    manual_cleaner.run(cache)

    assert manual_cleaner.last_interval == wake_up


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("flush_max", [1, 10, 100])
def test_acp_flush_max_buffers(pyocf_ctx, manual_cleaner, cls, flush_max):
    """Verify each cleaner iteration flushes at most flush_max_buffers
    cache lines."""
    cache, core, vol, queue = setup_cache(pyocf_ctx, cls=cls)

    io_size = Size.from_MiB(10)
    fill_dirty(vol, queue, Size(0), io_size)

    total_clines = io_size // Size(cls)
    blocks_per_cline = Size(cls) // STATS_BLOCK_SIZE

    cache.set_cleaning_policy_param(
        CleaningPolicy.ACP, AcpParams.WAKE_UP_TIME, 0
    )
    cache.set_cleaning_policy_param(
        CleaningPolicy.ACP, AcpParams.FLUSH_MAX_BUFFERS, flush_max
    )
    cache.set_cleaning_policy(CleaningPolicy.ACP)

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
