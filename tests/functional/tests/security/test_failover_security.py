#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
import logging
from datetime import datetime

from pyocf.types.volume_cache import CacheVolume
from pyocf.types.volume import RamVolume
from pyocf.types.cache import Cache, CacheMetadataSegment, CacheMode
from pyocf.utils import Size
from pyocf.types.shared import CacheLineSize, OcfError, OcfErrorCode
from pyocf.types.ctx import OcfCtx
from pyocf.rio import Rio, ReadWrite
from pyocf.helpers import get_metadata_segment_size, get_metadata_segment_page_location
from tests.utils.random import RandomGenerator

logger = logging.getLogger(__name__)


@pytest.mark.security
@pytest.mark.parametrize("cache_line_size", CacheLineSize)
@pytest.mark.parametrize(
    "bs",
    [
        Size.from_B(512),
        Size.from_KiB(1),
        Size.from_KiB(18),
        Size.from_KiB(128),
    ],
)
@pytest.mark.parametrize(
    "io_size",
    [
        Size.from_B(512),
        Size.from_KiB(10),
        Size.from_MiB(1),
        Size.from_MiB(10),
        Size.from_GiB(1),
    ],
)
@pytest.mark.parametrize("section", CacheMetadataSegment)
def test_garbage_on_cache_exported_object(pyocf_ctx, cache_line_size, bs, io_size, section):
    num_jobs = 1
    qd = 64

    vol_size = Size.from_MiB(100)
    cache_vol = RamVolume(vol_size)
    secondary_cache_volume = RamVolume(vol_size)

    cache = Cache(owner=OcfCtx.get_default(), cache_line_size=cache_line_size)

    cache.start_cache(init_default_io_queue=False)

    for i in range(num_jobs):
        cache.add_io_queue(f"io-queue-{i}")

    cache.standby_attach(cache_vol)

    cache_exp_vol = CacheVolume(cache)

    seed = next(RandomGenerator())
    r = (
        Rio()
        .target(cache_exp_vol)
        .njobs(num_jobs)
        .readwrite(ReadWrite.RANDWRITE)
        .io_size(io_size)
        .randseed(seed)
        .bs(bs)
        .qd(qd)
        .norandommap()
        .run(cache.io_queues)
    )

    cache.standby_detach()
    with pytest.raises(OcfError):
        cache.standby_activate(secondary_cache_volume, open_cores=False)
