#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import pytest
import math
import logging
import random
from ctypes import c_int

from pyocf.types.core import Core
from pyocf.types.volume import Volume
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.shared import OcfCompletion
from pyocf.types.cache import CacheMode, CacheLineSize, Cache
from pyocf.utils import Size
from tests.utils import start_cache_with_core

LOGGER = logging.getLogger(__name__)


# TODO: remove xfail when wb cache mode will be fixed
@pytest.mark.xfail
@pytest.mark.parametrize("cls", CacheLineSize)
def test_wb_flush_cache(pyocf_ctx, cls):
    cache_device, core_device, cache, core = start_cache_with_core(Size.from_MiB(30),
                                                                   Size.from_MiB(60),
                                                                   cache_mode=CacheMode.WB,
                                                                   cache_line_size=cls)
    stats_before_io = cache.get_stats()

    io_size = Size.from_MiB(10)
    run_io(core, cache.get_default_queue(), bytes(io_size.B), IoDir.WRITE)

    # Check cache usage statistics before flush
    stats_before_flush = cache.get_stats()
    assert stats_before_flush["usage"]["occupancy"]["value"] == stats_before_io["usage"]["occupancy"][
        "value"] + math.ceil(io_size.B / 4096)
    assert stats_before_flush["usage"]["dirty"]["value"] == math.ceil(io_size.B / 4096)
    assert stats_before_flush["usage"]["clean"]["value"] == stats_before_io["usage"]["clean"]["value"]
    assert core.exp_obj_md5() != core_device.md5()

    cache.flush()

    # Check cache usage statistics after flush
    stats_after_flush = cache.get_stats()
    assert stats_after_flush["usage"]["occupancy"]["value"] == stats_before_flush["usage"]["occupancy"]["value"]
    assert stats_after_flush["usage"]["dirty"]["value"] == 0
    assert stats_after_flush["usage"]["clean"]["value"] == stats_before_flush["usage"]["clean"]["value"] + math.ceil(
        io_size.B / 4096)
    assert core.exp_obj_md5() == core_device.md5()


# TODO: remove xfail when wb cache mode will be fixed
@pytest.mark.xfail
@pytest.mark.parametrize("cls", CacheLineSize)
def test_wb_stop_without_flushing(pyocf_ctx, cls):
    cache_device, core_device, cache, core = start_cache_with_core(Size.from_MiB(30),
                                                                   Size.from_MiB(60),
                                                                   cache_mode=CacheMode.WB,
                                                                   cache_line_size=cls)

    stats_before_io = cache.get_stats()

    io_size = Size.from_MiB(10)
    run_io(core, cache.get_default_queue(), bytes(io_size.B), IoDir.WRITE)

    stats_before_stop = cache.get_stats()

    # Check cache usage statistics before cache stop
    assert stats_before_stop["usage"]["occupancy"]["value"] == stats_before_io["usage"]["occupancy"][
        "value"] + math.ceil(io_size.B / 4096)
    assert stats_before_stop["usage"]["dirty"]["value"] == math.ceil(io_size.B / 4096)
    assert stats_before_stop["usage"]["clean"]["value"] == stats_before_io["usage"]["clean"]["value"]
    assert core.exp_obj_md5() != core_device.md5()

    cache.stop()
    cache.load_cache(cache_device)

    stats_after_stop_without_flush = cache.get_stats()

    # Check cache usage statistics after stopping cache without flush
    assert stats_after_stop_without_flush == stats_before_stop

    cache.flush()
    cache.stop()
    cache.load_cache(cache_device)

    # Check cache usage statistics after stopping cache with flush
    stats_after_stop_with_flush = cache.get_stats()
    assert stats_after_stop_with_flush["usage"]["occupancy"]["value"] == stats_before_stop["usage"]["occupancy"][
        "value"]
    assert stats_after_stop_with_flush["usage"]["dirty"]["value"] == 0
    assert stats_after_stop_with_flush["usage"]["clean"]["value"] == stats_before_io["usage"]["clean"][
        "value"] + math.ceil(io_size.B / 4096)
    assert core.exp_obj_md5() == core_device.md5()


# TODO: remove xfail when wb cache mode will be fixed
@pytest.mark.xfail
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("cm", [CacheMode.PT, CacheMode.WA, CacheMode.WT, CacheMode.WI])
def test_wb_change_cache_mode(pyocf_ctx, cls, cm):
    cache_device, core_device, cache, core = start_cache_with_core(Size.from_MiB(30),
                                                                   Size.from_MiB(60),
                                                                   cache_mode=CacheMode.WB,
                                                                   cache_line_size=cls)

    stats_before_io = cache.get_stats()

    io_size = Size.from_MiB(10)
    run_io(core, cache.get_default_queue(), bytes(io_size.B), IoDir.WRITE)

    # Check cache usage statistics before cache mode change
    stats_before_change_cache_mode = cache.get_stats()
    assert stats_before_change_cache_mode["usage"]["occupancy"]["value"] == stats_before_io["usage"]["occupancy"][
        "value"] + math.ceil(io_size.B / 4096)
    assert stats_before_change_cache_mode["usage"]["dirty"]["value"] == math.ceil(io_size.B / 4096)
    assert stats_before_change_cache_mode["usage"]["clean"]["value"] == stats_before_io["usage"]["clean"]["value"]
    assert core.exp_obj_md5() != core_device.md5()

    cache.flush()
    cache.change_cache_mode(cm)

    # Check cache usage statistics after cache mode change
    stats_after = cache.get_stats()
    assert stats_after["usage"]["occupancy"]["value"] == stats_before_change_cache_mode["usage"]["occupancy"]["value"]
    assert stats_after["usage"]["dirty"]["value"] == 0
    assert stats_after["usage"]["clean"]["value"] == stats_before_change_cache_mode["usage"]["clean"][
        "value"] + math.ceil(io_size.B / 4096)
    assert core.exp_obj_md5() == core_device.md5()


# TODO: remove xfail when wb cache mode will be fixed
@pytest.mark.xfail
@pytest.mark.parametrize("cls", CacheLineSize)
def test_wb_flush_core(pyocf_ctx, cls):
    cache_device, core_device, cache, core = start_cache_with_core(Size.from_MiB(30),
                                                                   Size.from_MiB(60),
                                                                   cache_mode=CacheMode.WB,
                                                                   cache_line_size=cls)
    second_core_device = Volume(Size.from_MiB(60))
    second_core = Core.using_device(second_core_device)
    cache.add_core(second_core)
    core_device.reset_stats()

    cache_stats_before_io = cache.get_stats()
    core_stats_before_io = core.get_stats()
    second_core_stats_before_io = second_core.get_stats()

    io_size = Size.from_MiB(20)
    run_io(core, cache.get_default_queue(), bytes(io_size.B), IoDir.WRITE)
    run_io(second_core, cache.get_default_queue(), bytes(io_size.B), IoDir.WRITE)

    cache_stats_after_io = cache.get_stats()
    core_stats_after_io = core.get_stats()
    second_core_stats_after_io = second_core.get_stats()

    # Check cache statistics after IO
    assert cache_stats_after_io["usage"]["occupancy"]["value"] == cache_stats_before_io["usage"]["occupancy"][
        "value"] + 2 * math.ceil(io_size.B / 4096)
    assert cache_stats_after_io["usage"]["dirty"]["value"] == 2 * math.ceil(io_size.B / 4096)
    assert cache_stats_after_io["usage"]["clean"]["value"] == cache_stats_before_io["usage"]["clean"]["value"]

    # Check statistics of core, which IO was running on
    assert core_stats_after_io["usage"]["occupancy"]["value"] == core_stats_before_io["usage"]["occupancy"][
        "value"] + math.ceil(io_size.B / 4096)
    assert core_stats_after_io["usage"]["dirty"]["value"] == math.ceil(io_size.B / 4096)
    assert core_stats_after_io["usage"]["clean"]["value"] == core_stats_before_io["usage"]["clean"]["value"]

    # Check statistics of second core, which IO wasn't running on
    assert second_core_stats_after_io["usage"]["occupancy"]["value"] == \
        second_core_stats_before_io["usage"]["occupancy"]["value"] + math.ceil(io_size.B / 4096)
    assert second_core_stats_after_io["usage"]["dirty"]["value"] == math.ceil(io_size.B / 4096)
    assert second_core_stats_after_io["usage"]["clean"]["value"] == second_core_stats_before_io["usage"]["clean"][
        "value"]

    core.flush()

    cache_stats_after_core_flush = cache.get_stats()
    core_stats_after_core_flush = core.get_stats()
    second_core_stats_after_core_flush = second_core.get_stats()

    # Check cache statistics after core flush
    assert cache_stats_after_core_flush["usage"]["occupancy"]["value"] == cache_stats_after_io["usage"]["occupancy"][
        "value"]
    assert cache_stats_after_core_flush["usage"]["dirty"]["value"] == math.ceil(io_size.B / 4096)
    assert cache_stats_after_core_flush["usage"]["clean"]["value"] == cache_stats_after_io["usage"]["clean"][
        "value"] - math.ceil(io_size.B / 4096)

    # Check statistics of flushed core
    assert core_stats_after_core_flush["usage"]["occupancy"]["value"] == core_stats_after_io["usage"]["occupancy"][
        "value"]
    assert core_stats_after_core_flush["usage"]["dirty"]["value"] == 0
    assert core_stats_after_core_flush["usage"]["clean"]["value"] == core_stats_after_io["usage"]["clean"][
        "value"] + math.ceil(io_size.B / 4096)

    # Check if statistics of second core did not change after first core flushing
    assert second_core_stats_after_core_flush["usage"]["occupancy"]["value"] == \
        second_core_stats_after_io["usage"]["occupancy"]["value"]
    assert second_core_stats_after_core_flush["usage"]["dirty"]["value"] == \
        second_core_stats_after_io["usage"]["dirty"]["value"]
    assert second_core_stats_after_core_flush["usage"]["clean"]["value"] == \
        second_core_stats_after_io["usage"]["clean"]["value"]

    assert core.exp_obj_md5() == core_device.md5()
    assert second_core.exp_obj_md5() != second_core_device.md5()

    cache.remove_core(core)
    cache.remove_core(second_core)

    # Check cache usage statistics after removal of both core devices
    assert cache.get_stats()["usage"]["occupancy"]["value"] == 0
    assert cache.get_stats()["usage"]["dirty"]["value"] == 0
    assert cache.get_stats()["usage"]["clean"]["value"] == 0


# TODO: remove xfail when wb cache mode will be fixed
@pytest.mark.xfail
@pytest.mark.parametrize("cls", CacheLineSize)
def test_wb_100_flush(pyocf_ctx, cls):
    cache_device, core_device, cache, core = start_cache_with_core(Size.from_MiB(30),
                                                                   Size.from_MiB(60),
                                                                   cache_mode=CacheMode.WB,
                                                                   cache_line_size=cls)
    stats_before_io = cache.get_stats()
    for i in range(0, 100):
        io_size = Size.from_MiB(random.randint(1, 30))
        run_io(core, cache.get_default_queue(), bytes(io_size.B), IoDir.WRITE)

        cache.flush()

        # Check cache usage statistics after flush
        stats_after_flush = cache.get_stats()
        assert stats_after_flush["usage"]["occupancy"]["value"] == stats_before_io["usage"]["occupancy"][
            "value"] + math.ceil(io_size.B / 4096)
        assert stats_after_flush["usage"]["dirty"]["value"] == 0
        assert stats_after_flush["usage"]["clean"]["value"] == stats_before_io["usage"]["clean"]["value"] + math.ceil(
            io_size.B / 4096)
        assert core.exp_obj_md5() == core_device.md5()
        stats_before_io = stats_after_flush


@pytest.mark.parametrize("cls", CacheLineSize)
def test_wb_flush_50core(pyocf_ctx, cls):
    cache_device = Volume(Size.from_MiB(30))
    cache = Cache.start_on_device(cache_device, cache_mode=CacheMode.WB, cache_line_size=cls)
    core_devices = []
    core_exp_objects = []
    core_count = 50
    io_size = Size.from_MiB(10)

    for i in range(0, core_count):
        core_device = Volume(Size.from_MiB(20))
        core = Core.using_device(core_device)
        core_exp_objects.append(core)
        core_devices.append(core_device)
        cache.add_core(core)

    for i in range(0, core_count):
        run_io(core_exp_objects[i], cache.get_default_queue(), bytes(io_size.B), IoDir.WRITE)
        core_exp_objects[i].flush()
        assert core_exp_objects[i].exp_obj_md5() == core_devices[i].md5()


def run_io(device, queue, data, direction):
    write_data = Data.from_bytes(data)
    io = device.new_io()
    io.set_data(write_data)
    io.configure(0, write_data.size, direction, 0, 0)
    io.set_queue(queue)

    cmpl = OcfCompletion([("err", c_int)])
    io.callback = cmpl.callback
    io.submit()
    cmpl.wait()
    assert cmpl.results["err"] == 0
