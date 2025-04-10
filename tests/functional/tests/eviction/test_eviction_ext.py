#
# Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import logging
import pytest

from time import sleep

from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.shared import SeqCutOffPolicy, CacheLineSize
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.ocf_utils import assert_stats
from pyocf.utils import Size

from tests.eviction.test_eviction import send_io


logger = logging.getLogger(__name__)

cache_size_M = Size.from_MiB(50)
core_size_M = cache_size_M * 2
cache100_4K = cache_size_M.blocks_4k
cache90_4K = int(cache100_4K * 0.9)
cache80_4K = int(cache100_4K * 0.8)
cache70_4K = int(cache100_4K * 0.7)
cache20_4K = int(cache100_4K * 0.2)
cache10_4K = int(cache100_4K * 0.1)

def write_data(vol: CoreVolume, len: int, addr:int = 0):
	assert addr % 4096 == 0
	assert len % 4096 == 0
	size = Size.from_B(len)
	data = Data(size)
	send_io(vol, data, addr)
	return addr + len


def assert_usage(object_with_stats, **kwargs):
	assert_stats(object_with_stats, 'usage', **kwargs)

def init_test():
	cache_device = RamVolume(cache_size_M)
	cache = Cache.start_on_device(cache_device, cache_mode=CacheMode.WT, metadata_volatile=True)
	cache_size = cache.get_stats()["conf"]["size"]
	assert cache_size.blocks_4k == cache100_4K
	core_device = RamVolume(core_size_M)
	core = Core.using_device(core_device)
	cache.add_core(core)
	cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)
	vol = CoreVolume(core)
	# assert empty cache
	assert_usage(cache, occupancy=0, free=cache100_4K, clean=0, dirty=0)
	return cache, cache_size, core, vol

@pytest.mark.parametrize("cls", CacheLineSize)
def test_eviction_free_first(pyocf_ctx, cls: CacheLineSize):
	"""
	tests if eviction takes place from free list first.
	we observed strange behavior, where there are free cache lines, but
	instead of using them, we evict from the used cache lines.
	"""
	cache, cache_size, core, vol = init_test()
	# write data of size 90% of the cache
	next_addr = write_data(vol, int(cache_size.B * 0.9))
	# assert 90% full and 10% free cache
	assert_usage(cache, occupancy=cache90_4K, free=cache10_4K, clean=cache90_4K, dirty=0)
	stats = cache.get_stats()
	stat = stats['usage']
	assert stat['occupancy']['fraction'] == 9000
	assert stat['free']['fraction'] == 1000
	assert stat['clean']['fraction'] == 9000
	assert stat['dirty']['value'] == 0
	# write additional data (to a different address, cache miss) of size 20%
	# of the cache
	next_addr = write_data(vol, int(cache_size.B * 0.2), next_addr)
	# one would expect the 10% free space would be used, but in fact, OCF
	# tries to evict all the required 20% from the already used cache
	# lines. actual eviction takes place from the used cache lines,
	# possibly together with some free cache lines adjacent to the evicted
	# used cache lines. occupancy is 90% + epsilon < 100%.
	stats = cache.get_stats()
	stat = stats['usage']
	assert 9000 <= stat['occupancy']['fraction'] < 10000
	assert stat['free']['fraction'] <= 1000
	assert stat['dirty']['value'] == 0


@pytest.mark.parametrize("cls", CacheLineSize)
def test_eviction_free_first_with_dirty(pyocf_ctx, cls: CacheLineSize):
	"""
	tests if eviction takes place from free list first.
	similar to test_eviction_free_first, but this time, there are also
	dirty cache lines.
	"""
	cache, cache_size, core, vol = init_test()
	# write clean data of size 20% of the cache
	next_addr = write_data(vol, int(cache_size.B * 0.2))
	# assert 20% full (all clean), and 80% free cache
	assert_usage(cache, occupancy=cache20_4K, free=cache80_4K, clean=cache20_4K, dirty=0)
	# write dirty data of size 70% of the cache
	cache.change_cache_mode(CacheMode.WB)
	next_addr = write_data(vol, int(cache_size.B * 0.7), next_addr)
	# assert 90% full (20% clean and 70% dirty), and 10% free cache
	assert_usage(cache, occupancy=cache90_4K, free=cache10_4K, clean=cache20_4K, dirty=cache70_4K)
	# write clean data of size 20% of the cache
	cache.change_cache_mode(CacheMode.WT)
	next_addr = write_data(vol, int(cache_size.B * 0.2), next_addr)
	# one would expect the 10% free space would be used, but in fact, OCF
	# evicts all the required 20% from the already used CLEAN cache lines.
	# in addition, OCF has triggered a cleaning of 32 cache lines, so after
	# a short wait, occupancy should change to 20% + 32 cache lines clean,
	# 70% - 32 cache lines dirty, and 10% free.
	sleep(0.01)
	assert_usage(cache, occupancy=cache90_4K, free=cache10_4K, clean=cache20_4K+32, dirty=cache70_4K-32)


@pytest.mark.parametrize("cls", CacheLineSize)
def test_eviction_over60dirty(pyocf_ctx, cls: CacheLineSize):
	"""
	tests if eviction triggers cleaning if cache is more than 60% dirty.
	"""
	cache, cache_size, core, vol = init_test()
	# write clean data of size 20% of the cache
	next_addr = write_data(vol, int(cache_size.B * 0.2))
	# assert 20% full (all clean), and 80% free cache
	assert_usage(cache, occupancy=cache20_4K, free=cache80_4K, clean=cache20_4K, dirty=0)
	# write dirty data of size 80% of the cache
	cache.change_cache_mode(CacheMode.WB)
	next_addr = write_data(vol, int(cache_size.B * 0.8), next_addr)
	# assert 100% full (20% clean and 80% dirty) cache
	assert_usage(cache, occupancy=cache100_4K, free=0, clean=cache20_4K, dirty=cache80_4K)
	# write clean data of size 20% cache line of the cache
	cache.change_cache_mode(CacheMode.WT)
	next_addr = write_data(vol, int(cache_size.B * 0.1), next_addr)
	# since there are more than 60% dirty cache lines, a cleaing of 32 cache
	# lines should be triggered.
	# assert 20% + 32 clean and 80% - 32 dirty cache.
	sleep(0.01)
	assert_usage(cache, occupancy=cache100_4K, free=0, clean=cache20_4K+32, dirty=cache80_4K-32)
