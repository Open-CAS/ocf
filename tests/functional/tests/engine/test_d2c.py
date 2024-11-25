#
# Copyright(c) 2024 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#


from time import sleep
import pytest


from pyocf.types.cache import Cache
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import IoDir, Sync
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size

CORE_SIZE = 4096


def test_d2c_io(pyocf_ctx):
    """
    Start cache in D2C
    prepare an IO in D2C
    attach cache
    submit and complete an IO in WT
    submit the D2C IO
    read data from core
    verify the data read from core matches with content of the core disk
    """
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size(CORE_SIZE))

    cache = Cache(owner=pyocf_ctx)
    cache.start_cache()
    core = Core.using_device(core_device)
    cache.add_core(core)

    queue = cache.get_default_queue()
    vol = CoreVolume(core)
    vol.open()

    d2c_io = vol.new_io(queue, 0, CORE_SIZE, IoDir.WRITE, 0, 0)
    d2c_data = Data(CORE_SIZE)
    d2c_data.write(b"a" * CORE_SIZE, CORE_SIZE)
    d2c_io.set_data(d2c_data)

    c = cache.attach_device_async(cache_device)
    sleep(1)

    wt_io = vol.new_io(queue, 0, CORE_SIZE, IoDir.WRITE, 0, 0)
    wt_data = Data(CORE_SIZE)
    wt_data.write(b"b" * CORE_SIZE, CORE_SIZE)
    wt_io.set_data(wt_data)

    wt_completion = Sync(wt_io).submit()
    assert int(wt_completion.results["err"]) == 0

    d2c_completion = Sync(d2c_io).submit()
    assert int(d2c_completion.results["err"]) == 0

    c.wait()

    if c.results["error"]:
        raise OcfError(
            f"Attaching cache device failed",
            c.results["error"],
        )

    assert cache.get_stats()["req"]["wr_pt"]["value"] == 2

    read_io = vol.new_io(queue, 0, CORE_SIZE, IoDir.READ, 0, 0)
    read_data = Data(CORE_SIZE)
    read_io.set_data(read_data)

    read_completion = Sync(read_io).submit()
    assert int(read_completion.results["err"]) == 0
    assert cache.get_stats()["req"]["rd_full_misses"]["value"] == 1

    cache.stop()

    assert core_device.md5() == read_data.md5()
