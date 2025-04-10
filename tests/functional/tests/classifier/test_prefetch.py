#
# Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import pytest

from pyocf.types.core import Core
from pyocf.types.ocf_types import PrefetchAlgorithmId, PrefetchAlgorithmMask
from pyocf.ocf_utils import CoreContextManager, core_sync_read, assert_stats
from pyocf.utils import Size as S


PREFETCH_PART_ID = 2
CACHE_SIZE_MB = 50


def assert_prefetch_stats(object_with_stats, stat_key, prefetch_alg, **kwargs):
    stats = object_with_stats.get_stats()
    stat = stats[stat_key]
    for param_name in kwargs:
        expected = kwargs[param_name]
        actual = stat[param_name][prefetch_alg]['value']
        assert actual == expected,\
            f'stat[{repr(param_name)}][{prefetch_alg}][\'value\'] == {actual}' \
            f', kwargs[{repr(param_name)}] == {expected}'


def default_context():
    return CoreContextManager(CACHE_SIZE_MB, 60,
                              ocf_prefetcher=PrefetchAlgorithmMask.READAHEAD,
                              metadata_volatile=True, use_submit_fast=True)


def run_test_prefetch(core: Core, reads):
    """
    read sequentially 255+delta times. assert a prefetch of 20 was triggered.
    assert further delta reads are served from cache as read hits.
    """
    sequence = 255
    prefetches = 20
    assert sequence <= reads < sequence + prefetches
    cache = core.cache
    conf = cache.get_conf()
    page_size = conf["cache_line_size"]
    # do the first 255 reads
    for i in range(sequence):
        core_sync_read(core, address=page_size*i, size=page_size)
    cache.settle()
    assert_stats(cache, 'block',
        core_volume_rd=sequence,       # normal reads
        cache_volume_rd=0,             # read hits
        cache_volume_wr=sequence)      # read misses
    assert_prefetch_stats(cache, 'block', PrefetchAlgorithmId.STREAM,
        prefetch_core_rd=prefetches,   # prefetch reads
        prefetch_cache_wr=prefetches)  # writes of prefetch reads to cache
    # assert 20 cache lines in prefetch partition
    stats = cache.get_stats(part_id=PREFETCH_PART_ID)
    assert stats['usage']['occupancy']['value'] == prefetches
    # do the rest delta reads
    for i in range(sequence, reads):
        core_sync_read(core, address=page_size*i, size=page_size)
    cache.settle()
    delta = reads - sequence
    assert_stats(cache, 'block',
        core_volume_rd=sequence,       # normal reads
        cache_volume_rd=delta,         # read hits
        cache_volume_wr=sequence)      # read misses
    assert_prefetch_stats(cache, 'block', 2,
        prefetch_core_rd=prefetches,   # prefetch reads
        prefetch_cache_wr=prefetches)  # writes of prefetch reads to cache
    # assert 275-reads cache lines in prefetch partition
    stats = cache.get_stats(part_id=PREFETCH_PART_ID)
    assert stats['usage']['occupancy']['value'] == sequence + prefetches - reads
    # assert_stats(cache, 'req', rd_hits=reads - 255, rd_full_misses=255)
    # assert matching stats in core
    assert_stats(core, 'blocks', core_volume_rd=sequence,
        cache_volume_rd=delta, cache_volume_wr=sequence)
    assert_prefetch_stats(core, 'blocks', 2, prefetch_core_rd=prefetches,
        prefetch_cache_wr=prefetches)


@pytest.mark.skip
def test_prefetch_255(pyocf_ctx):
    with default_context() as core:
        run_test_prefetch(core, 255)


@pytest.mark.skip
def test_prefetch_260(pyocf_ctx):
    with default_context() as core:
        run_test_prefetch(core, 260)


@pytest.mark.skip
def test_prefetch_274(pyocf_ctx):
    with default_context() as core:
        run_test_prefetch(core, 274)


@pytest.mark.skip
def test_prefetch_bug1(pyocf_ctx):
    """
    Reproduce the following bug:
        Read sequentially 255 times *into a full cache*.
        Assert a prefetch of 20 was triggered.
        This is same as test_prefetch_255(), except that in test_prefetch_255()
        we start from an empty cache.
        We expect the same behavior, but instead we get no prefetch.
    The bug is that when the cache is full, prefetch data is not brought to
    cache at all because of its low evict priority. OCF doesn't evict from
    partition 0 in favour of prefetch partition, and because the prefetch read
    does not manage to acquire cache lines for the operation, it reverts to PT.
    """
    with default_context() as core:
        cache = core.cache
        MB = S.from_MiB(1).B
        for i in range(CACHE_SIZE_MB):
            core_sync_read(core, address=(i+2)*MB, size=MB)
        # assert CACHE_SIZE_MB amount of data was inserted to cache
        blocks_read = S.from_MiB(CACHE_SIZE_MB).blocks_4k
        assert_stats(cache, 'block', core_volume_rd=blocks_read,
            cache_volume_wr=blocks_read)
        # assert cache is full
        assert_stats(cache, 'usage', free=0, occupancy=blocks_read)
        assert cache.get_stats()['usage']['occupancy']['fraction'] == 10000
        # reset stats and run test_prefetch_255()
        cache.settle()
        cache.reset_stats()
        core.reset_stats()
        run_test_prefetch(core, 255)
