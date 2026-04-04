#
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

import math
import pytest

from pyocf.types.cache import Cache, CacheMode, PrefetchPolicy, ReadaheadParams
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size
from pyocf.types.shared import CacheLineSize, SeqCutOffPolicy
from pyocf.rio import Rio, ReadWrite
from pyocf.helpers import is_block_size_4k


PF_READAHEAD_MASK = 1 << PrefetchPolicy.READAHEAD
PF_READAHEAD_MIN = Size.from_KiB(64)
STATS_BLOCK_SIZE = Size.from_KiB(4)


def setup_cache_core(pyocf_ctx, cache_line_size=CacheLineSize.DEFAULT):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(100))

    cache = Cache.start_on_device(cache_device, cache_mode=CacheMode.WT,
                                  cache_line_size=cache_line_size)
    core = Core.using_device(core_device)
    cache.add_core(core)

    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    vol = CoreVolume(core)
    queue = cache.get_default_queue()

    return cache, core, vol, queue


def get_prefetch_count(cache):
    stats = cache.get_stats()
    return stats["req"]["prefetch"][0].value


def get_prefetch_blocks(cache):
    stats = cache.get_stats()
    return {
        "core_rd": stats["block"]["prefetch_core_rd"][0].value,
        "cache_wr": stats["block"]["prefetch_cache_wr"][0].value,
    }


def test_prefetch_policy_default(pyocf_ctx):
    """Check that the default prefetch policy mask is 0 (all disabled)."""
    cache_device = RamVolume(Size.from_MiB(50))
    cache = Cache.start_on_device(cache_device, cache_mode=CacheMode.WT)

    assert cache.get_prefetch_policy() == 0


def test_prefetch_readahead_params_default(pyocf_ctx):
    """Check that the default readahead threshold is 64 KiB."""
    cache_device = RamVolume(Size.from_MiB(50))
    cache = Cache.start_on_device(cache_device, cache_mode=CacheMode.WT)

    val = cache.get_prefetch_param(PrefetchPolicy.READAHEAD,
                                   ReadaheadParams.THRESHOLD)
    assert val == int(Size.from_KiB(64))


@pytest.mark.parametrize("threshold", [
    Size(0), Size.from_KiB(16), Size.from_KiB(64),
    Size.from_KiB(256), Size.from_MiB(4),
])
@pytest.mark.parametrize("req_size", [
    Size(512), Size.from_KiB(4), Size.from_KiB(64), Size.from_MiB(1),
])
@pytest.mark.parametrize("cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_64KiB])
def test_prefetch_readahead_threshold(pyocf_ctx, threshold, req_size, cls):
    """
    Submit sequential I/O just below the readahead threshold and verify
    that prefetch has not triggered. Then submit one more request and
    verify that prefetch triggers with expected request and block stats.
    """
    if is_block_size_4k() and req_size < Size.from_KiB(4):
        pytest.skip("Sub-4K I/O not supported in 4K block mode")

    cache, core, vol, queue = setup_cache_core(pyocf_ctx, cache_line_size=cls)

    cache.set_prefetch_policy(PF_READAHEAD_MASK)
    cache.set_prefetch_param(PrefetchPolicy.READAHEAD,
                             ReadaheadParams.THRESHOLD, int(threshold))

    # Readahead sees bytes from previous requests. After N requests it
    # sees (N-1)*req_size bytes. Submit max(1, ceil(threshold/req_size))
    # requests to stay below threshold.
    below_count = max(1, math.ceil(int(threshold) / int(req_size)))
    below_size = Size(below_count * int(req_size))

    rio = (Rio().target(vol).bs(req_size).size(below_size)
           .readwrite(ReadWrite.READ))
    rio.run([queue])
    queue.settle()

    assert get_prefetch_count(cache) == 0, \
        "No prefetch should trigger below threshold"
    assert get_prefetch_blocks(cache) == {"core_rd": 0, "cache_wr": 0}, \
        "No prefetch blocks should be generated below threshold"

    # Submit one more request - this one should trigger prefetch
    rio = (Rio().target(vol).bs(req_size).size(req_size).offset(below_size)
           .readwrite(ReadWrite.READ))
    rio.run([queue])
    queue.settle()

    assert get_prefetch_count(cache) == 1, \
        "Exactly one prefetch request should be generated"

    # Prefetch range = max(request cache lines, 64KiB worth of cache lines)
    req_lines = math.ceil(int(req_size) / cls)
    prefetch_lines = max(req_lines, int(PF_READAHEAD_MIN) // cls)
    # Block stats are reported in 4KiB units
    expected_blocks = prefetch_lines * cls // int(STATS_BLOCK_SIZE)

    blocks = get_prefetch_blocks(cache)
    assert blocks["core_rd"] == expected_blocks, \
        f"Expected {expected_blocks} 4KiB blocks read from core"
    assert blocks["cache_wr"] == expected_blocks, \
        f"Expected {expected_blocks} 4KiB blocks written to cache"


@pytest.mark.parametrize("cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_64KiB])
def test_prefetch_readahead_random(pyocf_ctx, cls):
    """
    Verify that random reads do not trigger prefetch.
    """
    cache, core, vol, queue = setup_cache_core(pyocf_ctx, cache_line_size=cls)

    cache.set_prefetch_policy(PF_READAHEAD_MASK)

    rio = (Rio().target(vol).bs(Size.from_KiB(4)).size(Size.from_MiB(20))
           .readwrite(ReadWrite.RANDREAD))
    rio.run([queue])
    queue.settle()

    assert get_prefetch_count(cache) == 0, \
        "No prefetch should trigger for random reads"


@pytest.mark.parametrize("cache_mode", [CacheMode.WT, CacheMode.WB,
                                        CacheMode.WA, CacheMode.WI])
@pytest.mark.parametrize("cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_64KiB])
def test_prefetch_readahead_read_insert(pyocf_ctx, cache_mode, cls):
    """
    Verify that prefetch triggers for all cache modes that insert reads
    (WT, WB, WA, WI).
    """
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(100))

    cache = Cache.start_on_device(cache_device, cache_mode=cache_mode,
                                  cache_line_size=cls)
    core = Core.using_device(core_device)
    cache.add_core(core)

    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)
    cache.set_prefetch_policy(PF_READAHEAD_MASK)
    cache.set_prefetch_param(PrefetchPolicy.READAHEAD,
                             ReadaheadParams.THRESHOLD, 0)

    vol = CoreVolume(core)
    queue = cache.get_default_queue()

    rio = (Rio().target(vol).bs(Size.from_KiB(4)).size(Size.from_MiB(1))
           .readwrite(ReadWrite.READ))
    rio.run([queue])
    queue.settle()

    assert get_prefetch_count(cache) > 0, \
        f"Prefetch should trigger in {cache_mode.name} mode"


@pytest.mark.parametrize("cache_mode", [CacheMode.PT, CacheMode.WO])
@pytest.mark.parametrize("cls", [CacheLineSize.LINE_4KiB, CacheLineSize.LINE_64KiB])
def test_prefetch_readahead_no_read_insert(pyocf_ctx, cache_mode, cls):
    """
    Verify that prefetch does not trigger when the effective cache mode
    does not insert reads (PT, WO).
    """
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(100))

    cache = Cache.start_on_device(cache_device, cache_mode=cache_mode,
                                  cache_line_size=cls)
    core = Core.using_device(core_device)
    cache.add_core(core)

    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)
    cache.set_prefetch_policy(PF_READAHEAD_MASK)
    cache.set_prefetch_param(PrefetchPolicy.READAHEAD,
                             ReadaheadParams.THRESHOLD, 0)

    vol = CoreVolume(core)
    queue = cache.get_default_queue()

    rio = (Rio().target(vol).bs(Size.from_KiB(4)).size(Size.from_MiB(1))
           .readwrite(ReadWrite.READ))
    rio.run([queue])
    queue.settle()

    assert get_prefetch_count(cache) == 0, \
        f"No prefetch should trigger in {cache_mode.name} mode"
