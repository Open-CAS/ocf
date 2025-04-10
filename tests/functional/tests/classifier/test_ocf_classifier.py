#
# Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import time
import pytest

from pyocf.ocf_utils import CoreContextManager, mbr_new, \
    mbr_set_partition_entry, mbr_memmove_to_disk, mbr_write_to_disk, \
    core_sync_read, core_sync_write, assert_stats, ocf_partitions_remove_swap_max_size_for_testing
from pyocf.utils import Size
from pyocf.types import volume
from pyocf.types.volume_core import CoreVolume
from pyocf.types.cache import UciClassifier


WT_REGION_START = Size.from_sector(256)
WB_REGION_START = Size.from_MiB(70)
WT_REGION_LENGTH = Size.from_B(WB_REGION_START.B - WT_REGION_START.B)
assert WT_REGION_LENGTH.MiB == 69
WB_REGION_LENGTH = Size.from_MiB(30)


def default_context():
    return CoreContextManager(50, 60, ocf_classifier=UciClassifier.ALL, metadata_volatile=True,
                                   use_submit_fast=True)


def pre_initialized_swap_partition(wb_region_start_sectors,
                                   wb_region_length_sectors):
    # create core device with swap partition
    core_device = volume.RamVolume(Size.from_MiB(100))
    mbr = mbr_new()
    mbr_set_partition_entry(mbr, 0, id=130, lba=wb_region_start_sectors,
                            sectors=wb_region_length_sectors)
    mbr_set_partition_entry(mbr, 1, id=0, lba=0, sectors=0)
    mbr_memmove_to_disk(core_device, mbr)
    # create cache over partitioned core device
    return CoreContextManager(50, core_device, ocf_classifier=UciClassifier.ALL,
                              metadata_volatile=True, use_submit_fast=True)


def post_initialized_swap_partition(wb_region_start_sectors,
                                    wb_region_length_sectors):
    # create cache over a clean non-partitioned core device
    result = CoreContextManager(50, 100, ocf_classifier=UciClassifier.ALL,
                                metadata_volatile=True, use_submit_fast=True)
    # create swap partition in core device. cache should detect it.
    mbr = mbr_new()
    mbr_set_partition_entry(mbr, 0, id=130, lba=wb_region_start_sectors,
                            sectors=wb_region_length_sectors)
    mbr_set_partition_entry(mbr, 1, id=0, lba=0, sectors=0)
    vol = CoreVolume(result.core)
    vol.open()
    queue = result.cache.get_default_queue()
    mbr_write_to_disk(vol, queue, mbr)
    vol.close()
    # now we have a used cache line. free it.
    result.cache.purge()
    # verify clean cache and reset stats
    assert_stats(result.cache, 'usage', occupancy=0, clean=0, dirty=0)
    result.cache.reset_stats()
    assert_stats(result.cache, 'req', rd_total=0, wr_total=0)
    return result


def test_ocf_classifier_bad_init(caplog, pyocf_ctx):
    """
    Initialize ocf with OCF classifier enabled, and with forbidden parameter
    metadata_volatile=False.
    This should override user's request and set metadata_volatile=True, but
    causes segmentation fault instead (before the fix).
    """
    with CoreContextManager(50, 60, allow_override_defaults=False,
            name="cache",
            metadata_volatile=False,
            ocf_classifier=UciClassifier.ALL) as core:
        cache_stats = core.cache.get_stats()
        # assert ocf classifier is on
        assert cache_stats["conf"]["ocf_classifier"] == UciClassifier.ALL
        # assert metadata is volatile
        assert cache_stats["conf"]["metadata_end_offset"].B == 0
    # assert error message was printed
    assert "cache: metadata_volatile forced to 1" in caplog.text


def test_submit_io_fast(pyocf_ctx):
    """
    Initialize ocf with OCF classifier enabled, and with correct parameters
    use_submit_fast=True.
    This fails (before the fix), because the test infrastructure always sets
    use_submit_fast=False regardless of the specified parameters.
    """
    default_context()


@pytest.mark.parametrize("core_context_func",
                         [pre_initialized_swap_partition,
                          post_initialized_swap_partition])
def test_ocf_classifier_write_and_read(pyocf_ctx, core_context_func):
    """
    Basic test for OCF classifier.
    1. Start cache with OCF classifier enabled
    2. Write to WT region and check that cache line is clean + read to verify
    3. Write to WB region and check that cache line is dirty + read to verify
    """
    wb_start = WB_REGION_START.linux_sectors
    wb_length = WB_REGION_LENGTH.linux_sectors
    with core_context_func(wb_start, wb_length) as core:
        cache = core.cache
        # write to WT area
        wt_address = WT_REGION_START.B
        core_sync_write(core, wt_address, b'1234567890')
        # assert one write with a write miss
        assert_stats(cache, 'req', rd_total=0)
        assert_stats(cache, 'req', wr_total=1, wr_hits=0, wr_partial_misses=0, wr_full_misses=1)
        # assert one new cache line in clean state
        assert_stats(cache, 'usage', occupancy=1, clean=1, dirty=0)
        # read to verify
        s = core_sync_read(core, wt_address, 10)
        # assert one additional read with one read hit
        assert_stats(cache, 'req', rd_total=1, rd_hits=1, rd_partial_misses=0, rd_full_misses=0)
        assert_stats(cache, 'req', wr_total=1, wr_hits=0, wr_partial_misses=0, wr_full_misses=1)
        # assert no change in cache lines state
        assert_stats(cache, 'usage', occupancy=1, clean=1, dirty=0)
        assert s == b'1234567890'
        # write to WB area
        wb_address = WB_REGION_START.B + 4096
        core_sync_write(core, wb_address, b'abcdefg')
        # assert one additional write with one write miss
        assert_stats(cache, 'req', rd_total=1, rd_hits=1, rd_partial_misses=0, rd_full_misses=0)
        assert_stats(cache, 'req', wr_total=2, wr_hits=0, wr_partial_misses=0, wr_full_misses=2)
        # assert one new cache line in dirty state
        print(cache.get_stats()['usage'])
        assert_stats(cache, 'usage', occupancy=2, clean=1, dirty=1)
        # read to verify
        s = core_sync_read(core, wb_address, 7)
        # assert one additional read with one read hit
        assert_stats(cache, 'req', rd_total=2, rd_hits=2, rd_partial_misses=0, rd_full_misses=0)
        assert_stats(cache, 'req', wr_total=2, wr_hits=0, wr_partial_misses=0, wr_full_misses=2)
        # assert no change cache lines state
        assert_stats(cache, 'usage', occupancy=2, clean=1, dirty=1)
        assert s == b'abcdefg'
        # write again to WT area same address
        core_sync_write(core, wt_address, b'1234567890')
        # assert one additional write with one write hit
        assert_stats(cache, 'req', rd_total=2, rd_hits=2, rd_partial_misses=0, rd_full_misses=0)
        assert_stats(cache, 'req', wr_total=3, wr_hits=1, wr_partial_misses=0, wr_full_misses=2)
        # assert no change cache lines state
        assert_stats(cache, 'usage', occupancy=2, clean=1, dirty=1)
        s = core_sync_read(core, wt_address, 10)
        # assert one additional read with one read hit
        assert_stats(cache, 'req', rd_total=3, rd_hits=3, rd_partial_misses=0, rd_full_misses=0)
        assert_stats(cache, 'req', wr_total=3, wr_hits=1, wr_partial_misses=0, wr_full_misses=2)
        # assert no change cache lines state
        assert_stats(cache, 'usage', occupancy=2, clean=1, dirty=1)
        assert s == b'1234567890'


@pytest.mark.parametrize("core_context_func",
                         [pre_initialized_swap_partition,
                          post_initialized_swap_partition])
@pytest.mark.long
def test_all_WT_one_WB(pyocf_ctx, core_context_func):
    """
    Writes one cache line to WB area, and lots of cache lines (more than cache
    size) to WT area.
    Expected result: dirty cache line is not evicted.
    """
    wb_start = WB_REGION_START.sectors
    wb_length = WB_REGION_LENGTH.sectors
    with core_context_func(wb_start, wb_length) as core:
        cache = core.cache
        cache_size = cache.get_stats()["conf"]["size"]
        assert cache_size < WT_REGION_LENGTH.B
        block = cache.cache_line_size.value
        assert block == 4096
        # Write to WB area just one block
        wb_address = WB_REGION_START.B + Size.from_MiB(1).B
        core_sync_write(core, wb_address, b'WB data')
        # assert one dirty block
        assert_stats(cache, 'usage', occupancy=1, clean=0, dirty=1)
        # Write to WT area more than cache size
        wt_blocks = WT_REGION_LENGTH.blocks_4k
        j = 0
        while j < cache_size.blocks_4k * 2:
            for i in range(wt_blocks):
                s = bytes(f'write #{i}', 'ascii')
                core_sync_write(core, WT_REGION_START.B + (i * block), s)
                assert_stats(cache, 'usage', dirty=1)
                j += 1
        # assert cache is full, and dirty block is still there
        assert_stats(cache, 'usage', occupancy=cache_size.blocks_4k,
                     clean=cache_size.blocks_4k - 1, dirty=1)
        # verify WB data and assert read hit
        assert_stats(cache, 'req', rd_total=0, rd_hits=0, rd_partial_misses=0, rd_full_misses=0)
        s = core_sync_read(core, wb_address, 7)
        assert_stats(cache, 'req', rd_total=1, rd_hits=1, rd_partial_misses=0, rd_full_misses=0)
        assert s == b'WB data'
        for i in range(wt_blocks):
            expected_s = bytes(f'write #{i}', 'ascii')
            actual_s = core_sync_read(core, WT_REGION_START.B + (i * block),
                                 len(expected_s))
            assert expected_s == actual_s


@pytest.mark.parametrize("core_context_func",
                         [pre_initialized_swap_partition,
                          post_initialized_swap_partition])
def test_all_WB_one_WT(pyocf_ctx, core_context_func):
    """
    Fills cache with dirty data by writing to the WB area an amount of data
    equal to cache size.
    Then writes one block to WT area.
    Expected result: 32 clean cache lines, all the rest are dirty.
    """
    wb_start = Size.from_MiB(30).linux_sectors
    wb_length = Size.from_MiB(60).linux_sectors
    with core_context_func(wb_start, wb_length) as core:
        cache = core.cache
        ocf_partitions_remove_swap_max_size_for_testing(cache)
        cache_size = cache.get_stats()["conf"]["size"]
        block = cache.cache_line_size.value
        # Write to WB area a cache size amount of data
        wb_address = wb_start * Size.from_linux_sector(1).B
        for i in range(cache_size.blocks_4k):
            s = bytes(f'write-back #{i}', 'ascii')
            core_sync_write(core, (i * block) + wb_address, s)
        # assert cache full and all blocks are dirty
        assert_stats(cache, 'usage', occupancy=cache_size.blocks_4k,
                     clean=0, dirty=cache_size.blocks_4k)
        # Write to WT area just one cache line
        wt_address = Size.from_MiB(90).B
        core_sync_write(core, wt_address, b'WT data')
        time.sleep(0.1)  # wait for stats to update
        print(cache.get_stats()['usage'])
        # assert 32 clean blocks due to ocf_lru_clean()
        assert_stats(cache, 'usage', occupancy=cache_size.blocks_4k,
                     clean=32, dirty=cache_size.blocks_4k - 32)
        # verify data
        s = core_sync_read(core, wt_address, 7)
        assert s == b'WT data'
        for i in range(cache_size.blocks_4k):
            expected_s = bytes(f'write-back #{i}', 'ascii')
            actual_s = core_sync_read(core, i * block + wb_address, len(expected_s))
            assert expected_s == actual_s
