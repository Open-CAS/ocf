#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import pytest

from pyocf.types.cache import Cache
from pyocf.types.core import Core
from pyocf.types.volume import Volume, ErrorDevice
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.queue import Queue
from pyocf.utils import Size as S
from pyocf.types.shared import OcfError


def test_ctx_fixture(pyocf_ctx):
    pass


def test_adding_cores(pyocf_ctx):
    cache_device = Volume(S.from_MiB(200))
    core1_device = Volume(S.from_MiB(400))
    core2_device = Volume(S.from_MiB(400))

    cache = Cache.start_on_device(cache_device)
    core1 = Core.using_device(core1_device)
    core2 = Core.using_device(core2_device)

    cache.add_core(core1)
    cache.add_core(core2)


def test_adding_core_twice(pyocf_ctx):
    cache_device = Volume(S.from_MiB(200))
    core_device = Volume(S.from_MiB(400))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)

    cache.add_core(core)
    with pytest.raises(OcfError):
        cache.add_core(core)


def test_simple_wt_write(pyocf_ctx):
    cache_device = Volume(S.from_MiB(100))
    core_device = Volume(S.from_MiB(200))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)

    queue = Queue(cache)
    cache.add_core(core)

    cache_device.reset_stats()
    core_device.reset_stats()

    write_data = Data.from_string("This is test data")
    io = core.new_io()
    io.set_data(write_data)
    io.configure(20, write_data.size, IoDir.WRITE, 0, 0)
    io.set_queue(queue)
    io.submit()

    assert cache_device.get_stats()[IoDir.WRITE] == 1
    stats = cache.get_stats()
    assert stats["req"]["wr_full_misses"]["value"] == 1
    assert stats["usage"]["occupancy"]["value"] == 1

    assert core.exp_obj_md5() == core_device.md5()


def test_start_corrupted_metadata_lba(pyocf_ctx):
    cache_device = ErrorDevice(S.from_MiB(100), error_sectors=set([0]))

    with pytest.raises(OcfError, match="OCF_ERR_WRITE_CACHE"):
        cache = Cache.start_on_device(cache_device)


def test_load_cache_no_preexisting_data(pyocf_ctx):
    cache_device = Volume(S.from_MiB(100))

    with pytest.raises(OcfError, match="OCF_ERR_INVAL"):
        cache = Cache.load_from_device(cache_device)


# TODO: Find out why this fails and fix
@pytest.mark.xfail
def test_load_cache(pyocf_ctx):
    cache_device = Volume(S.from_MiB(100))

    cache = Cache.start_on_device(cache_device)
    cache.stop()

    cache = Cache.load_from_device(cache_device)
