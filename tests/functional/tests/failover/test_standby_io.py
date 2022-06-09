#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
from datetime import timedelta

from pyocf.types.volume import RamVolume
from pyocf.types.volume_cache import CacheVolume
from pyocf.types.cache import Cache, CacheMetadataSegment
from pyocf.types.queue import Queue
from pyocf.utils import Size
from pyocf.types.shared import CacheLineSize
from pyocf.types.ctx import OcfCtx
from pyocf.rio import Rio, ReadWrite
from pyocf.helpers import get_metadata_segment_page_location, get_metadata_segment_size


@pytest.mark.parametrize("cacheline_size", CacheLineSize)
def test_test_standby_io(pyocf_ctx, cacheline_size):
    num_jobs = 8
    qd = 16
    runtime = 5

    vol_size = Size.from_MiB(100)
    cache_vol = RamVolume(vol_size)

    cache = Cache(owner=OcfCtx.get_default(), cache_line_size=cacheline_size)

    cache.start_cache(init_default_io_queue=False)

    for i in range(num_jobs):
        cache.add_io_queue(f"io-queue-{i}")

    cache.standby_attach(cache_vol)
    cache_vol = CacheVolume(cache, open=True)

    r = (
        Rio()
        .target(cache_vol)
        .njobs(num_jobs)
        .readwrite(ReadWrite.RANDWRITE)
        .size(vol_size)
        .io_size(Size.from_GiB(100))
        .bs(Size.from_KiB(4))
        .qd(qd)
        .time(timedelta(seconds=runtime))
        .time_based()
        .run(cache.io_queues)
    )


@pytest.mark.parametrize("cacheline_size", CacheLineSize)
def test_test_standby_io_metadata(pyocf_ctx, cacheline_size):
    num_jobs = 8
    qd = 16
    runtime = 10

    vol_size = Size.from_MiB(200)
    cache_vol = RamVolume(vol_size)

    cache = Cache(owner=OcfCtx.get_default(), cache_line_size=cacheline_size)

    cache.start_cache(init_default_io_queue=False)

    for i in range(num_jobs):
        cache.add_io_queue(f"io-queue-{i}")

    cache.standby_attach(cache_vol)

    start = get_metadata_segment_page_location(cache, CacheMetadataSegment.COLLISION)
    count = get_metadata_segment_size(cache, CacheMetadataSegment.COLLISION)
    io_offset = Size.from_page(start)
    io_size = Size.from_page(count)

    cache_vol = CacheVolume(cache, open=True)

    r = (
        Rio()
        .target(cache_vol)
        .njobs(num_jobs)
        .readwrite(ReadWrite.RANDWRITE)
        .size(io_offset + io_size)
        .bs(Size.from_KiB(16))
        .offset(io_offset)
        .qd(qd)
        .time(timedelta(seconds=runtime))
        .time_based()
        .norandommap()
        .run(cache.io_queues)
    )
