#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import c_int, memmove, cast, c_void_p
from enum import IntEnum
from itertools import product
import random

from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.volume import Volume
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.utils import Size
from pyocf.types.shared import OcfCompletion


def __io(io, queue, address, size, data, direction):
    io.set_data(data, 0)
    completion = OcfCompletion([("err", c_int)])
    io.callback = completion.callback
    io.submit()
    completion.wait()
    return int(completion.results['err'])


def _io(new_io, queue, address, size, data, offset, direction):
    io = new_io(queue, address, size, direction, 0, 0)
    if direction == IoDir.READ:
        _data = Data.from_bytes(bytes(size))
    else:
        _data = Data.from_bytes(data, offset, size)
    ret = __io(io, queue, address, size, _data, direction)
    if not ret and direction == IoDir.READ:
        memmove(cast(data, c_void_p).value + offset, _data.handle, size)
    return ret


def io_to_core(core, address, size, data, offset, direction):
    return _io(core.new_core_io, core.cache.get_default_queue(), address, size,
               data, offset, direction)


def io_to_exp_obj(core, address, size, data, offset, direction):
    return _io(core.new_io, core.cache.get_default_queue(), address, size, data,
               offset, direction)


def sector_to_region(sector, region_start):
    i = 0
    while i < len(region_start) - 1 and sector >= region_start[i + 1]:
        i += 1
    return i


class SectorStatus(IntEnum):
    DIRTY = 0,
    CLEAN = 1,
    INVALID = 2,


I = SectorStatus.INVALID
D = SectorStatus.DIRTY
C = SectorStatus.CLEAN

# Test reads with 4k cacheline and different combinations of sectors status and
# IO range. Three consecutive core lines are targeted, with the middle one (no 1)
# having all sectors status (clean, dirty, invalid) set independently. The other
# two lines either are fully dirty/clean/invalid or have the single sector
# neighbouring with middle core line with different status. This gives total of
# 12 regions with independent state, listed on the diagram below.
#
# cache line        | CL 0   |  CL 1  | CL 2   |
# sector no         |01234567|89ABCDEF|(ctd..) |
#                   |........|........|........|
# region no         |00000001|23456789|ABBBBBBB|
# io start possible |        |        |        |
#   values @START   |>     >>|>>>>>>>>|        |
# io end possible   |        |        |        |
#   values @END     |        |<<<<<<<<|<<     <|
#
# Each test iteration is described by region states and IO start/end sectors,
# giving total of 14 parameters
#
# In order to determine data consistency, cache is filled with data so so that:
# - core sector no @n is filled with @n
# - if clean, exported object sector no @n is filled with 100 + @n
# - if dirty, exported object sector no @n is filled with 200 + @n
#


def test_wo_read_data_consistency(pyocf_ctx):
    # start sector for each region
    region_start = [0, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
    # possible start sectors for test iteration
    start_sec = [0, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    # possible end sectors for test iteration
    end_sec = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 23]

    CACHELINE_COUNT = 3
    CACHELINE_SIZE = 4096
    SECTOR_SIZE = Size.from_sector(1).B
    CLS = CACHELINE_SIZE // SECTOR_SIZE
    WORKSET_SIZE = CACHELINE_COUNT * CACHELINE_SIZE
    WORKSET_OFFSET = 1024 * CACHELINE_SIZE
    SECTOR_COUNT = int(WORKSET_SIZE / SECTOR_SIZE)
    ITRATION_COUNT = 200

    # fixed test cases
    fixed_combinations = [
        [I, I, D, D, D, D, D, D, D, D, I, I],
        [I, I, C, C, C, C, C, C, C, C, I, I],
        [I, I, D, D, D, I, D, D, D, D, I, I],
        [I, I, D, D, D, I, I, D, D, D, I, I],
        [I, I, I, I, D, I, I, D, C, D, I, I],
        [I, D, D, D, D, D, D, D, D, D, D, I],
        [C, C, I, D, D, I, D, D, D, D, D, I],
        [D, D, D, D, D, D, D, D, D, D, D, I],
    ]

    data = {}
    # memset n-th sector of core data with n
    data[SectorStatus.INVALID] = bytes([x // SECTOR_SIZE for x in range(WORKSET_SIZE)])
    # memset n-th sector of clean data with n + 100
    data[SectorStatus.CLEAN] = bytes([100 + x // SECTOR_SIZE for x in range(WORKSET_SIZE)])
    # memset n-th sector of dirty data with n + 200
    data[SectorStatus.DIRTY] = bytes([200 + x // SECTOR_SIZE for x in range(WORKSET_SIZE)])

    result_b = bytes(WORKSET_SIZE)

    cache_device = Volume(Size.from_MiB(30))
    core_device = Volume(Size.from_MiB(30))

    cache = Cache.start_on_device(cache_device, cache_mode=CacheMode.WO)
    core = Core.using_device(core_device)

    cache.add_core(core)

    insert_order = [x for x in range(CACHELINE_COUNT)]

    # generate regions status combinations and shuffle it
    combinations = []
    state_combinations = product(SectorStatus, repeat=len(region_start))
    for S in state_combinations:
        combinations.append(S)
    random.shuffle(combinations)

    # add fixed test cases at the beginning
    combinations = fixed_combinations + combinations

    for S in combinations[:ITRATION_COUNT]:
        # write data to core and invalidate all CL
        cache.change_cache_mode(cache_mode=CacheMode.PT)
        io_to_exp_obj(core, WORKSET_OFFSET, len(data[SectorStatus.INVALID]),
                      data[SectorStatus.INVALID], 0, IoDir.WRITE)

        # randomize cacheline insertion order to exercise different
        # paths with regard to cache I/O physical addresses continuousness
        random.shuffle(insert_order)
        sectors = [insert_order[i // CLS] * CLS + (i % CLS) for i in range(SECTOR_COUNT)]

        # insert clean sectors - iterate over cachelines in @insert_order order
        cache.change_cache_mode(cache_mode=CacheMode.WT)
        for sec in sectors:
            region = sector_to_region(sec, region_start)
            if S[region] != SectorStatus.INVALID:
                io_to_exp_obj(core, WORKSET_OFFSET + SECTOR_SIZE * sec, SECTOR_SIZE,
                              data[SectorStatus.CLEAN], sec * SECTOR_SIZE, IoDir.WRITE)

        # write dirty sectors
        cache.change_cache_mode(cache_mode=CacheMode.WO)
        for sec in sectors:
            region = sector_to_region(sec, region_start)
            if S[region] == SectorStatus.DIRTY:
                io_to_exp_obj(core, WORKSET_OFFSET + SECTOR_SIZE * sec, SECTOR_SIZE,
                              data[SectorStatus.DIRTY], sec * SECTOR_SIZE, IoDir.WRITE)

        core_device.reset_stats()

        for s in start_sec:
            for e in end_sec:
                if s > e:
                    continue

                # issue WO read
                START = s * SECTOR_SIZE
                END = e * SECTOR_SIZE
                size = (e - s + 1) * SECTOR_SIZE
                assert 0 == io_to_exp_obj(
                    core, WORKSET_OFFSET + START, size, result_b, START, IoDir.READ
                ), "error reading in WO mode: S={}, start={}, end={}, insert_order={}".format(
                    S, s, e, insert_order
                )

                # verify read data
                for sec in range(s, e + 1):
                    # just check the first byte of sector
                    region = sector_to_region(sec, region_start)
                    check_byte = sec * SECTOR_SIZE
                    assert (
                        result_b[check_byte] == data[S[region]][check_byte]
                    ), "unexpected data in sector {}, S={}, s={}, e={}, insert_order={}\n".format(
                        sec, S, s, e, insert_order
                    )

                # WO is not supposed to clean dirty data
                assert (
                    core_device.get_stats()[IoDir.WRITE] == 0
                ), "unexpected write to core device, S={}, s={}, e={}, insert_order = {}\n".format(
                    S, s, e, insert_order
                )
