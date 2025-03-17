#
# Copyright(c) 2019-2022 Intel Corporation
# Copyright(c) 2024-2025 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#

import logging
from ctypes import c_void_p, memmove, cast

import pytest
from pyocf.types.cache import (
    Cache,
    CacheMode,
    CleaningPolicy,
)
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import IoDir, Sync
from pyocf.types.shared import (
    CacheLines,
    CacheLineSize,
    SeqCutOffPolicy,
    OcfError,
)
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size

logger = logging.getLogger(__name__)


def test_add_remove_core_detached_cache(pyocf_ctx):
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache(owner=pyocf_ctx)
    cache.start_cache()
    core = Core.using_device(core_device)
    cache.add_core(core)
    cache.remove_core(core)
    cache.stop()


def test_attach_cache_twice(pyocf_ctx):
    cache_device_1 = RamVolume(Size.from_MiB(50))
    cache_device_2 = RamVolume(Size.from_MiB(50))

    cache = Cache(owner=pyocf_ctx)
    cache.start_cache()

    cache.attach_device(cache_device_1)

    with pytest.raises(OcfError, match="Attaching cache device failed"):
        cache.attach_device(cache_device_2)

    cache.stop()


def test_detach_cache_twice(pyocf_ctx):
    cache_device = RamVolume(Size.from_MiB(50))
    cache = Cache.start_on_device(cache_device)

    cache.detach_device()

    with pytest.raises(OcfError, match="Detaching cache device failed"):
        cache.detach_device()

    cache.stop()


@pytest.mark.parametrize("cleaning_policy", CleaningPolicy)
def test_detach_cache_with_cleaning(pyocf_ctx, cleaning_policy):
    cache_device = RamVolume(Size.from_MiB(100))
    core_device = RamVolume(Size.from_MiB(100))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)

    cache.add_core(core)

    cache.set_cleaning_policy(cleaning_policy)

    cache.detach_device()

    cache.stop()


def test_detach_cache_zero_superblock(pyocf_ctx):
    """Check if superblock is zeroed after detach and the cache device can be reattached without
    --force option.
    """
    cache_device = RamVolume(Size.from_MiB(50))
    cache = Cache.start_on_device(cache_device)

    cache.detach_device()

    data = cache_device.get_bytes()

    page_size = 4096
    assert data[:page_size] == b'\x00'*page_size

    cache.attach_device(cache_device, force=False)
    cache.detach_device()

    cache.stop()


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("mode", [CacheMode.WB, CacheMode.WT, CacheMode.WO])
@pytest.mark.parametrize("new_cache_size", [80, 120])
def test_attach_different_size(pyocf_ctx, new_cache_size, mode: CacheMode, cls: CacheLineSize):
    """Start cache and add partition with limited occupancy. Fill partition with data,
    attach cache with different size and trigger IO. Verify if occupancy threshold is
    respected with both original and new cache device.
    """
    cache_device = RamVolume(Size.from_MiB(100))
    core_device = RamVolume(Size.from_MiB(100))
    cache = Cache.start_on_device(cache_device, cache_mode=mode, cache_line_size=cls)
    core = Core.using_device(core_device)
    cache.add_core(core)

    vol = CoreVolume(core)
    queue = cache.get_default_queue()

    cache.configure_partition(part_id=1, name="test_part", max_size=50, priority=1)

    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    cache_size = cache.get_stats()["conf"]["size"]

    block_size = 4096
    data = bytes(block_size)

    for i in range(cache_size.blocks_4k):
        io_to_exp_obj(vol, queue, block_size * i, block_size, data, 0, IoDir.WRITE, 1, 0)

    part_current_size = CacheLines(cache.get_partition_info(part_id=1)["_curr_size"], cls)

    assert part_current_size.blocks_4k == cache_size.blocks_4k * 0.5

    cache.detach_device()
    new_cache_device = RamVolume(Size.from_MiB(new_cache_size))
    cache.attach_device(new_cache_device, force=True)

    cache_size = cache.get_stats()["conf"]["size"]

    for i in range(cache_size.blocks_4k):
        io_to_exp_obj(vol, queue, block_size * i, block_size, data, 0, IoDir.WRITE, 1, 0)

    part_current_size = CacheLines(cache.get_partition_info(part_id=1)["_curr_size"], cls)

    assert part_current_size.blocks_4k == cache_size.blocks_4k * 0.5


def io_to_exp_obj(vol, queue, address, size, data, offset, direction, target_ioclass, flags):
    vol.open()
    io = vol.new_io(queue, address, size, direction, target_ioclass, flags)
    if direction == IoDir.READ:
        _data = Data.from_bytes(bytes(size))
    else:
        _data = Data.from_bytes(data, offset, size)
    ret = __io(io, _data)
    if not ret and direction == IoDir.READ:
        memmove(cast(data, c_void_p).value + offset, _data.handle, size)
    vol.close()
    return ret


def __io(io, data):
    io.set_data(data, 0)
    completion = Sync(io).submit()
    return int(completion.results["err"])
