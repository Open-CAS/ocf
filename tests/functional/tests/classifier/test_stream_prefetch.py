#
# Copyright(c) 2022-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from pyocf.ocf_utils import CoreContextManager, core_sync_read, assert_stats
from pyocf.types.cache import CacheMode, UciClassifier
from pyocf.types.ocf_types import PrefetchAlgorithmMask
import pytest

CACHE_LINE_SIZE=4096
def get_prefetches_from_cache_stats(cache):
    return sum([i['value'] for i in cache.get_stats()['req']['prefetches']])
def get_prefetched_blocks_from_cache_stats(cache, cache_lines):
    return sum([i['value'] for i in cache.get_stats()['block']['prefetch_core_rd']])
class SequentialReader(object):
    """
    This is the main class used for testing the prefetcher
    It first creates upon initialization a read of X size
    """
    def __init__(self, core, min_reads_to_trigger_prefetch, probabilities_not_to_run_read, length):
        self.core=core
        self.cache=core.cache
        self.length=length
        self.cache_lines=int(self.length/CACHE_LINE_SIZE)
        """ Used for initialization to create sequences no greater then that, each sequence will have this is number as the gap in address"""
        self.max_number_of_reads_in_sequence=int((len(probabilities_not_to_run_read)+3)*self.cache_lines)

        self.reads_so_far = 0
        for i in range(min_reads_to_trigger_prefetch):

            for idx, pct in enumerate(probabilities_not_to_run_read):
                if i % 100 >=pct:
                    core_sync_read(core, i * length * self.max_number_of_reads_in_sequence + length*idx, length)
                    self.reads_so_far += 1

        self.cache.settle()
        self.read_hits_so_far=self.cache.get_stats()['req']['rd_hits']['value']
        self.blocks_read_so_far=self.cache.get_stats()['conf']['occupancy'].blocks_4k
        assert_stats(self.cache, 'req', rd_total=self.reads_so_far)

        """ Perform a read which will not trigger a prefetch"""
        i += 1
        self.cur_address = i * length * self.max_number_of_reads_in_sequence

        """ count prefetches so far"""
        self.prefetches=get_prefetches_from_cache_stats(self.cache)

        self.prefetched_blocks = get_prefetched_blocks_from_cache_stats(self.cache, self.cache_lines)

    def perform_read(self, is_hit, prefetch_length):
        """ This function performs a single read and evaluate if it behaved as expected
        It receives the expected status of the read (Was it a hit, did it create a prefetch request)"""
        core_sync_read(self.core, self.cur_address, self.length, should_sleep=True)
        self.reads_so_far+=1
        self.blocks_read_so_far+=prefetch_length*self.cache_lines
        if is_hit:
            self.read_hits_so_far+=1
        else:
            self.blocks_read_so_far +=self.cache_lines
        self.cur_address+=self.length
        self.cache.settle()
        assert self.cache.get_stats()['conf']['occupancy'].blocks_4k==self.blocks_read_so_far
        assert_stats(self.cache, 'req', rd_total=self.reads_so_far, rd_hits=self.read_hits_so_far)

        """ Test prefetches"""
        if prefetch_length > 0:
            self.prefetches+=1
            self.prefetched_blocks+=prefetch_length*self.cache_lines
        actual_prefetches=get_prefetches_from_cache_stats(self.cache)
        actual_prefetched_blocks=get_prefetched_blocks_from_cache_stats(self.cache, self.cache_lines)
        assert self.prefetches==actual_prefetches
        assert self.prefetched_blocks==actual_prefetched_blocks


def run_single_test(cache_size, core_size, probabilities_not_to_run_read, list_of_read_hit_statuses, list_of_prefetch_lengths, min_reads_to_trigger_prefetch, length=CACHE_LINE_SIZE):
    """
    This function runs a full test for prefetcher
    The test is comprised of initialization and testing

    The initialization is meant to construct the main data strcture containing probabilities for sequence length

    These are the parameters we use:
    probabilities_not_to_run_read:
        For the initialization, it determines how many sequential reads will be perform in each iteration and the probability they will be performed

        So if the value is [0,10, 20, 30] it means that at most 4 reads will be performed in each iteration,
        The first read will surely be performed, the second with (100-10)%=90% probability of being performed and so on

        The goal is to fill the DS so that a prefetch will occur as we want it to
    list_of_read_hit_statuses + list_of_prefetch_lengths:
        These two lists represent the execution part
        Each item in the lists is a read. we will perform and the result we expect
        Hence the 2 lists must be of the same length

        list_of_read_hit_statuses means if we have read hit or miss
        list_of_prefetch_lengths means if we perform a prefetch

        So, for example if list_of_read_hit_statuses=[True, False] and list_of_prefetch_lengths=[0,1] it means the first read will be ahit and the second will trigger
        a prefetch of length 1
    """
    with CoreContextManager(cache_size, core_size, ocf_classifier=UciClassifier.SWAP,
                            ocf_prefetcher=PrefetchAlgorithmMask.STREAM) as core:

        sequential_reader=SequentialReader(core=core,
                                           min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch
                                           , probabilities_not_to_run_read=probabilities_not_to_run_read,
                                           length=length)
        for is_hit, prefetch_length in zip(list_of_read_hit_statuses, list_of_prefetch_lengths):
            sequential_reader.perform_read(is_hit=is_hit, prefetch_length=prefetch_length)

@pytest.mark.skip
def test_basic_prefetch_single_sector(pyocf_ctx):
    probabilities_not_to_run_read = [0, 0]
    list_of_read_hit_statuses = [False, True, False, False]
    list_of_prefetch_lengths = [1, 0, 0, 0]
    min_reads_to_trigger_prefetch = 511
    run_single_test(cache_size=50, core_size=100,probabilities_not_to_run_read=probabilities_not_to_run_read,
                    list_of_read_hit_statuses=list_of_read_hit_statuses,
                    list_of_prefetch_lengths=list_of_prefetch_lengths,
                    min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch)

@pytest.mark.skip
def test_basic_prefetch_single_sector_not_100_pct(pyocf_ctx):
    probabilities_not_to_run_read = [0, 10]
    list_of_read_hit_statuses = [False, True, False, False]
    list_of_prefetch_lengths = [1, 0, 0, 0]
    min_reads_to_trigger_prefetch = 511
    run_single_test(cache_size=50, core_size=100,probabilities_not_to_run_read=probabilities_not_to_run_read,
                    list_of_read_hit_statuses=list_of_read_hit_statuses,
                    list_of_prefetch_lengths=list_of_prefetch_lengths,
                    min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch)

@pytest.mark.skip
def test_basic_prefetch_2_sectors(pyocf_ctx):
    probabilities_not_to_run_read = [0]*3
    list_of_read_hit_statuses = [False, True, True, False]
    list_of_prefetch_lengths = [2, 0, 0, 0]
    min_reads_to_trigger_prefetch = 511
    run_single_test(cache_size=50, core_size=100,probabilities_not_to_run_read=probabilities_not_to_run_read,
                    list_of_read_hit_statuses=list_of_read_hit_statuses,
                    list_of_prefetch_lengths=list_of_prefetch_lengths,
                    min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch)

@pytest.mark.skip
def test_basic_prefetch_2_sectors_not_100_pct(pyocf_ctx):
    """ Test case where the first read prefetches 2 additional block, after which no additional prefetch occur when moving forward in the sequence
        The prefetch mechansim relies on 90% probability of success"""

    probabilities_not_to_run_read = [0, 10, 10]
    list_of_read_hit_statuses = [False, True, True, False]
    list_of_prefetch_lengths = [2, 0, 0, 0]
    min_reads_to_trigger_prefetch = 511
    run_single_test(cache_size=50, core_size=100,probabilities_not_to_run_read=probabilities_not_to_run_read,
                    list_of_read_hit_statuses=list_of_read_hit_statuses,
                    list_of_prefetch_lengths=list_of_prefetch_lengths,
                    min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch)

@pytest.mark.skip
def test_prefetch_after_second(pyocf_ctx):
    probabilities_not_to_run_read = [0, 20, 30]
    list_of_read_hit_statuses = [False, False, True, False]
    list_of_prefetch_lengths = [0, 1, 0, 0]
    min_reads_to_trigger_prefetch = 800
    run_single_test(cache_size=50, core_size=100,probabilities_not_to_run_read=probabilities_not_to_run_read,
                    list_of_read_hit_statuses=list_of_read_hit_statuses,
                    list_of_prefetch_lengths=list_of_prefetch_lengths,
                    min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch)

@pytest.mark.skip
def test_multiple_prefetches_for_long_stream_too_small(pyocf_ctx):
    """ long sequence with varying percentages
    The third IO will trigger 3 prefetched blocks.
    Then the seventh should have triggered more but it will have less then 512 reads in the matrix so it won't run"""
    probabilities_not_to_run_read = [0, 21, 42, 43, 44, 45, 66, 67, 68, 69, 90]
    list_of_read_hit_statuses = [False, False, False, True, True, True, False, False, False, False, False]
    list_of_prefetch_lengths = [0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    min_reads_to_trigger_prefetch = 1000
    run_single_test(cache_size=60, core_size=120,probabilities_not_to_run_read=probabilities_not_to_run_read,
                    list_of_read_hit_statuses=list_of_read_hit_statuses,
                    list_of_prefetch_lengths=list_of_prefetch_lengths,
                    min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch)


@pytest.mark.skip
def test_prefetch_when_hit_occurs(pyocf_ctx):
    """ long sequence with varying percentages
    The third IO will trigger 3 prefetched blocks.
    Then the seventh trigger 3 prefetched blocks

    It is the same as previous test but with tripple read size
    """
    probabilities_not_to_run_read = [0, 5, 10, 15, 25, 30, 35, 40, 45]
    list_of_read_hit_statuses = [False, True, True, True, True, True, True, True, True, False]
    list_of_prefetch_lengths = [3, 0, 1, 1, 1, 1, 1, 0, 0, 0]
    min_reads_to_trigger_prefetch = 1000
    run_single_test(cache_size=100, core_size=200,probabilities_not_to_run_read=probabilities_not_to_run_read,
                    list_of_read_hit_statuses=list_of_read_hit_statuses,
                    list_of_prefetch_lengths=list_of_prefetch_lengths,
                    min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch)


@pytest.mark.skip
def test_multiple_prefetches_for_long_stream(pyocf_ctx):
    """ long sequence with varying percentages
    The third IO will trigger 3 prefetched blocks.
    Then the seventh trigger 3 prefetched blocks"""
    probabilities_not_to_run_read = [0, 21, 42, 43, 44, 45, 66, 67, 68, 69, 90]
    list_of_read_hit_statuses = [False, False, False, True, True, True, False, True, True, True, False]
    list_of_prefetch_lengths = [0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 0, 0]
    min_reads_to_trigger_prefetch = 2000
    run_single_test(cache_size=100, core_size=200,probabilities_not_to_run_read=probabilities_not_to_run_read,
                    list_of_read_hit_statuses=list_of_read_hit_statuses,
                    list_of_prefetch_lengths=list_of_prefetch_lengths,
                    min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch)

@pytest.mark.skip
def test_multiple_prefetches_for_long_stream_tripple_len(pyocf_ctx):
    """ long sequence with varying percentages
    The third IO will trigger 3 prefetched blocks.
    Then the seventh trigger 3 prefetched blocks

    It is the same as previous test but with tripple read size
    """
    probabilities_not_to_run_read = [0, 21, 42, 43, 44, 45, 66, 67, 68, 69, 90]
    list_of_read_hit_statuses = [False, False, False, True, True, True, False, True, True, True, False]
    list_of_prefetch_lengths = [0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 0, 0]
    min_reads_to_trigger_prefetch = 2000
    run_single_test(cache_size=300, core_size=1000,probabilities_not_to_run_read=probabilities_not_to_run_read,
                    list_of_read_hit_statuses=list_of_read_hit_statuses,
                    list_of_prefetch_lengths=list_of_prefetch_lengths,
                    min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch, length=CACHE_LINE_SIZE*3)

@pytest.mark.skip
def test_long_sequence(pyocf_ctx):
    """ long IO sequence which will generate a 20 read ahead"""
    probabilities_not_to_run_read = [0]*254
    list_of_read_hit_statuses = [False]+ 253*[True]+[False]+ 50*[True]
    list_of_prefetch_lengths = [253]+253*[0]+[20]+50*[1]
    min_reads_to_trigger_prefetch = 511
    run_single_test(cache_size=1000, core_size=2000,probabilities_not_to_run_read=probabilities_not_to_run_read,
                    list_of_read_hit_statuses=list_of_read_hit_statuses,
                    list_of_prefetch_lengths=list_of_prefetch_lengths,
                    min_reads_to_trigger_prefetch=min_reads_to_trigger_prefetch)

