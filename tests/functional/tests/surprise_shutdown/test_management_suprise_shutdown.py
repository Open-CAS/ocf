# Copyright(c) 2019-2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
from ctypes import c_int, c_void_p, byref, cast, POINTER

from pyocf.types.cache import Cache
from pyocf.types.core import Core
from pyocf.types.volume import ErrorDevice, Volume
from pyocf.types.io import IoDir
from pyocf.utils import Size as S
from pyocf.types.shared import (
    OcfError,
    OcfErrorCode,
    Uuid,
)
from pyocf.ocf import OcfLib


def mngmt_op_surprise_shutdown_test(
    pyocf_ctx, mngt_func, prepare_func, consistency_check_func
):
    error_triggered = True
    error_io_seq_no = 0

    while error_triggered:
        # Start cache device without error injection
        error_io = {IoDir.WRITE: error_io_seq_no}
        device = ErrorDevice(S.from_MiB(36), io_seq_no=error_io, armed=False)
        cache = Cache.start_on_device(device)

        if prepare_func:
            prepare_func(cache)

        # make sure cache state is persistent
        cache.save()

        # initiate error injection starting at write no @error_io_seq_no
        device.arm()

        # call tested management function
        status = 0
        try:
            mngt_func(cache)
        except OcfError as ex:
            status = ex.error_code

        # if error was injected we expect mngmt op error
        error_triggered = device.error_triggered()
        assert error_triggered == (status != 0)
        if error_triggered:
            assert status == OcfErrorCode.OCF_ERR_WRITE_CACHE

        # stop cache with error injection still on
        status = cache.stop()
        assert status == OcfErrorCode.OCF_ERR_WRITE_CACHE

        # disable error injection and load the cache
        device.disarm()
        cache = Cache.load_from_device(device)

        # run consistency check
        consistency_check_func(cache, error_triggered)

        # stop the cache
        cache.stop()

        # advance error injection point
        error_io_seq_no += 1


# power failure during core insert
def test_surprise_shutdown_add_core(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))
    core = Core.using_device(core_device)

    def check_core(cache, error_triggered):
        stats = cache.get_stats()
        assert stats["conf"]["core_count"] == (0 if error_triggered else 1)

    def tested_func(cache):
        cache.add_core(core)

    def check_func(cache, error_triggered):
        check_core(cache, error_triggered)

    mngmt_op_surprise_shutdown_test(pyocf_ctx, tested_func, None, check_func)


# power failure during core removal
def test_surprise_shutdown_remove_core(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))
    core = Core.using_device(core_device)

    def prepare_func(cache):
        cache.add_core(core)

    def tested_func(cache):
        cache.remove_core(core)

    def check_func(cache, error_triggered):
        stats = cache.get_stats()
        assert stats["conf"]["core_count"] == (1 if error_triggered else 0)

    mngmt_op_surprise_shutdown_test(pyocf_ctx, tested_func, prepare_func, check_func)


# power failure during core add after previous core removed
def test_surprise_shutdown_swap_core(pyocf_ctx):
    core_device_1 = Volume(S.from_MiB(10), uuid="dev1")
    core_device_2 = Volume(S.from_MiB(10), uuid="dev2")
    core1 = Core.using_device(core_device_1, name="core1")
    core2 = Core.using_device(core_device_2, name="core2")

    def prepare(cache):
        cache.add_core(core1)
        cache.save()
        cache.remove_core(core1)
        cache.save()

    def tested_func(cache):
        cache.add_core(core2)

    def check_func(cache, error_triggered):
        stats = cache.get_stats()
        assert stats["conf"]["core_count"] == (0 if error_triggered else 1)
        core1_ptr = c_void_p()
        core2_ptr = c_void_p()
        ret1 = OcfLib.getInstance().ocf_core_get_by_name(
            cache, "core1".encode("utf-8"), 6, byref(core1_ptr)
        )
        ret2 = OcfLib.getInstance().ocf_core_get_by_name(
            cache, "core2".encode("utf-8"), 6, byref(core2_ptr)
        )
        assert ret1 != 0
        if error_triggered:
            assert ret2 != 0
        else:
            assert ret2 == 0
            uuid_ptr = cast(
                cache.owner.lib.ocf_core_get_uuid_wrapper(core2_ptr), POINTER(Uuid)
            )
            uuid = str(uuid_ptr.contents._data, encoding="ascii")
            assert uuid == "dev2"

    mngmt_op_surprise_shutdown_test(pyocf_ctx, tested_func, prepare, check_func)
