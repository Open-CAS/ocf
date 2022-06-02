#
# Copyright(c) 2019-2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import logging
from ctypes import c_int, c_void_p, byref, c_uint32, memmove, cast
from random import randrange
from itertools import count

import pytest

from pyocf.ocf import OcfLib
from pyocf.types.cache import (
    Cache,
    CacheMode,
    MetadataLayout,
    CleaningPolicy,
)
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.shared import (
    OcfError,
    OcfCompletion,
    CacheLines,
    CacheLineSize,
    SeqCutOffPolicy,
)
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("mode", [CacheMode.WB, CacheMode.WT, CacheMode.WO])
@pytest.mark.parametrize("new_cache_size", [80, 120])
def test_attach_different_size(pyocf_ctx, new_cache_size, mode: CacheMode, cls: CacheLineSize):
    """Start cache and add partition with limited occupancy. Fill partition with data,
    attach cache with different size and trigger IO. Verify if occupancy thresold is
    respected with both original and new cache device.
    """
    cache_device = RamVolume(Size.from_MiB(100))
    core_device = RamVolume(Size.from_MiB(100))
    cache = Cache.start_on_device(cache_device, cache_mode=mode, cache_line_size=cls)
    core = Core.using_device(core_device)
    cache.add_core(core)

    vol = CoreVolume(core, open=True)
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
    io = vol.new_io(queue, address, size, direction, target_ioclass, flags)
    if direction == IoDir.READ:
        _data = Data.from_bytes(bytes(size))
    else:
        _data = Data.from_bytes(data, offset, size)
    ret = __io(io, queue, address, size, _data, direction)
    if not ret and direction == IoDir.READ:
        memmove(cast(data, c_void_p).value + offset, _data.handle, size)
    return ret


def __io(io, queue, address, size, data, direction):
    io.set_data(data, 0)
    completion = OcfCompletion([("err", c_int)])
    io.callback = completion.callback
    io.submit()
    completion.wait()
    return int(completion.results["err"])
