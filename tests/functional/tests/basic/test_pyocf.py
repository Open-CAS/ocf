#
# Copyright(c) 2019-2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
from ctypes import c_int

from pyocf.types.cache import Cache
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume, ErrorDevice
from pyocf.types.volume_core import CoreVolume
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.utils import Size as S
from pyocf.types.shared import OcfError, OcfCompletion
from pyocf.rio import Rio, ReadWrite


def test_ctx_fixture(pyocf_ctx):
    pass


def test_simple_wt_write(pyocf_ctx):
    cache_device = RamVolume(S.from_MiB(50))
    core_device = RamVolume(S.from_MiB(50))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)
    queue = cache.get_default_queue()

    cache.add_core(core)
    vol = CoreVolume(core, open=True)

    cache_device.reset_stats()
    core_device.reset_stats()

    r = Rio().target(vol).readwrite(ReadWrite.WRITE).size(S.from_sector(1)).run([queue])
    assert cache_device.get_stats()[IoDir.WRITE] == 1
    cache.settle()
    stats = cache.get_stats()
    assert stats["req"]["wr_full_misses"]["value"] == 1
    assert stats["usage"]["occupancy"]["value"] == 1

    assert vol.md5() == core_device.md5()
    cache.stop()


def test_start_corrupted_metadata_lba(pyocf_ctx):
    ramdisk = RamVolume(S.from_MiB(50))
    cache_device = ErrorDevice(ramdisk, error_sectors=set([0]))

    with pytest.raises(OcfError, match="OCF_ERR_WRITE_CACHE"):
        cache = Cache.start_on_device(cache_device)


def test_load_cache_no_preexisting_data(pyocf_ctx):
    cache_device = RamVolume(S.from_MiB(50))

    with pytest.raises(OcfError, match="OCF_ERR_NO_METADATA"):
        cache = Cache.load_from_device(cache_device)


def test_load_cache(pyocf_ctx):
    cache_device = RamVolume(S.from_MiB(50))

    cache = Cache.start_on_device(cache_device)
    cache.stop()

    cache = Cache.load_from_device(cache_device)


def test_load_cache_recovery(pyocf_ctx):
    cache_device = RamVolume(S.from_MiB(50))

    cache = Cache.start_on_device(cache_device)

    device_copy = cache_device.get_copy()

    cache.stop()

    cache = Cache.load_from_device(device_copy)


@pytest.mark.parametrize("open_cores", [True, False])
def test_load_cache_with_cores(pyocf_ctx, open_cores):
    cache_device = RamVolume(S.from_MiB(40))
    core_device = RamVolume(S.from_MiB(40))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device, name="test_core")

    cache.add_core(core)
    vol = CoreVolume(core, open=True)

    write_data = Data.from_string("This is test data")
    io = vol.new_io(
        cache.get_default_queue(), S.from_sector(3).B, write_data.size, IoDir.WRITE, 0, 0
    )
    io.set_data(write_data)

    cmpl = OcfCompletion([("err", c_int)])
    io.callback = cmpl.callback
    io.submit()
    cmpl.wait()

    cache.stop()

    cache = Cache.load_from_device(cache_device, open_cores=open_cores)
    if not open_cores:
        cache.add_core(core, try_add=True)
    else:
        core = cache.get_core_by_name("test_core")

    vol = CoreVolume(core, open=True)

    read_data = Data(write_data.size)
    io = vol.new_io(cache.get_default_queue(), S.from_sector(3).B, read_data.size, IoDir.READ, 0, 0)
    io.set_data(read_data)

    cmpl = OcfCompletion([("err", c_int)])
    io.callback = cmpl.callback
    io.submit()
    cmpl.wait()

    assert read_data.md5() == write_data.md5()
    assert vol.md5() == core_device.md5()
