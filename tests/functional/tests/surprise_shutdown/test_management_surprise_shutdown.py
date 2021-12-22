# Copyright(c) 2021-2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
from ctypes import c_int, c_void_p, byref, cast, POINTER

from pyocf.types.cache import (
    Cache,
    CacheMode,
    CleaningPolicy,
    SeqCutOffPolicy,
    PromotionPolicy,
    AlruParams,
    AcpParams,
    NhitParams,
)
from pyocf.types.data import Data
from pyocf.types.core import Core
from pyocf.types.volume import ErrorDevice, Volume
from pyocf.types.io import IoDir
from pyocf.types.ioclass import IoClassesInfo, IoClassInfo
from pyocf.utils import Size as S
from pyocf.types.shared import (
    OcfCompletion,
    CacheLineSize,
    OcfError,
    OcfErrorCode,
    Uuid,
)
from pyocf.ocf import OcfLib

mngmt_op_surprise_shutdown_test_cache_size = S.from_MiB(36)
mngmt_op_surprise_shutdown_test_io_offset = S.from_MiB(4).B


def ocf_write(cache, core, val, offset):
    data = Data.from_bytes(bytes([val] * 512))
    comp = OcfCompletion([("error", c_int)])
    io = core.new_io(cache.get_default_queue(), offset, 512, IoDir.WRITE, 0, 0)
    io.set_data(data)
    io.callback = comp.callback
    io.submit()
    comp.wait()


def ocf_read(cache, core, offset):
    data = Data(byte_count=512)
    comp = OcfCompletion([("error", c_int)])
    io = core.new_io(cache.get_default_queue(), offset, 512, IoDir.READ, 0, 0)
    io.set_data(data)
    io.callback = comp.callback
    io.submit()
    comp.wait()
    return data.get_bytes()[0]


def mngmt_op_surprise_shutdown_test(
    pyocf_ctx, mngt_func, prepare_func, consistency_check_func
):
    error_triggered = True
    error_io_seq_no = 0

    while error_triggered:
        # Start cache device without error injection
        error_io = {IoDir.WRITE: error_io_seq_no}
        device = ErrorDevice(
            mngmt_op_surprise_shutdown_test_cache_size, armed=False, error_seq_no=error_io
        )
        cache = Cache.start_on_device(device, cache_mode=CacheMode.WB)

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
            assert (
                status == OcfErrorCode.OCF_ERR_WRITE_CACHE
                or status == OcfErrorCode.OCF_ERR_IO
            )

        # stop cache with error injection still on
        with pytest.raises(OcfError) as ex:
            cache.stop()
        assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE

        # disable error injection and load the cache
        device.disarm()

        # load cache with open_cores = False to allow consistency check to add
        # core with WA for pyocf object management
        cache = Cache.load_from_device(device, open_cores=False)

        # run consistency check
        if consistency_check_func is not None:
            consistency_check_func(cache, error_triggered)

        # stop the cache
        cache.stop()

        # advance error injection point
        error_io_seq_no += 1


# power failure during core insert
@pytest.mark.security
def test_surprise_shutdown_add_core(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))

    def check_core(cache, error_triggered):
        stats = cache.get_stats()
        assert stats["conf"]["core_count"] == (0 if error_triggered else 1)

    def tested_func(cache):
        core = Core(device=core_device, try_add=False)
        cache.add_core(core)

    def check_func(cache, error_triggered):
        check_core(cache, error_triggered)

    mngmt_op_surprise_shutdown_test(pyocf_ctx, tested_func, None, check_func)


# power failure during core removal
@pytest.mark.security
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


@pytest.mark.security
def test_surprise_shutdown_remove_core_with_data(pyocf_ctx):
    io_offset = mngmt_op_surprise_shutdown_test_io_offset
    core_device = Volume(S.from_MiB(10))
    core = Core.using_device(core_device)

    def prepare_func(cache):
        cache.add_core(core)
        ocf_write(cache, core, 0xAA, io_offset)

    def tested_func(cache):
        cache.flush()
        cache.remove_core(core)

    def check_func(cache, error_triggered):
        stats = cache.get_stats()
        if stats["conf"]["core_count"] == 0:
            assert core_device.get_bytes()[io_offset] == 0xAA
        else:
            core = Core(device=core_device, try_add=True)
            cache.add_core(core)
            assert ocf_read(cache, core, io_offset) == 0xAA

    mngmt_op_surprise_shutdown_test(pyocf_ctx, tested_func, prepare_func, check_func)


# power failure during core add after previous core removed
@pytest.mark.security
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


# power failure during core add after previous core removed
@pytest.mark.security
def test_surprise_shutdown_swap_core_with_data(pyocf_ctx):
    core_device_1 = Volume(S.from_MiB(10), uuid="dev1")
    core_device_2 = Volume(S.from_MiB(10), uuid="dev2")
    core1 = Core.using_device(core_device_1, name="core1")
    core2 = Core.using_device(core_device_2, name="core2")

    def prepare(cache):
        cache.add_core(core1)
        cache.save()
        ocf_write(cache, core1, 0xAA, mngmt_op_surprise_shutdown_test_io_offset)
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
        if ret2 == 0:
            uuid_ptr = cast(
                cache.owner.lib.ocf_core_get_uuid_wrapper(core2_ptr), POINTER(Uuid)
            )
            uuid = str(uuid_ptr.contents._data, encoding="ascii")
            assert uuid == "dev2"
            core2 = Core(device=core_device_2, try_add=True, name="core2")
            cache.add_core(core2)
            assert (
                ocf_read(cache, core2, mngmt_op_surprise_shutdown_test_io_offset)
                == Volume.VOLUME_POISON
            )

    mngmt_op_surprise_shutdown_test(pyocf_ctx, tested_func, prepare, check_func)


# make sure there are no crashes when cache start is interrupted
#    1. is this checksum mismatch actually expected and the proper way
#       to avoid loading improperly initialized cache?
#    2. uuid checksum mismatch should not allow cache to load
@pytest.mark.security
def test_surprise_shutdown_start_cache(pyocf_ctx):
    error_triggered = True
    error_io_seq_no = 0

    while error_triggered:
        # Start cache device without error injection
        error_io = {IoDir.WRITE: error_io_seq_no}
        device = ErrorDevice(
            mngmt_op_surprise_shutdown_test_cache_size, error_seq_no=error_io, armed=True
        )

        # call tested management function
        status = 0
        try:
            cache = Cache.start_on_device(device, cache_mode=CacheMode.WB)
        except OcfError as ex:
            status = ex.error_code

        # if error was injected we expect mngmt op error
        error_triggered = device.error_triggered()
        assert error_triggered == (status != 0)

        if not error_triggered:
            # stop cache with error injection still on
            with pytest.raises(OcfError) as ex:
                cache.stop()
            assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE
            break

        # disable error injection and load the cache
        device.disarm()
        cache = None

        try:
            cache = Cache.load_from_device(device)
        except OcfError:
            cache = None

        if cache is not None:
            cache.stop()

        # advance error injection point
        error_io_seq_no += 1


@pytest.mark.security
def test_surprise_shutdown_stop_cache(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))
    error_triggered = True
    error_io_seq_no = 0
    io_offset = mngmt_op_surprise_shutdown_test_io_offset

    while error_triggered:
        # Start cache device without error injection
        error_io = {IoDir.WRITE: error_io_seq_no}
        device = ErrorDevice(
            mngmt_op_surprise_shutdown_test_cache_size, error_seq_no=error_io, armed=False
        )

        # setup cache and insert some data
        cache = Cache.start_on_device(device, cache_mode=CacheMode.WB)
        core = Core(device=core_device, try_add=False)
        cache.add_core(core)
        ocf_write(cache, core, 0xAA, io_offset)

        # start error injection
        device.arm()

        try:
            cache.stop()
            status = OcfErrorCode.OCF_OK
        except OcfError as ex:
            status = ex.error_code

        # if error was injected we expect mngmt op error
        error_triggered = device.error_triggered()
        if error_triggered:
            assert status == OcfErrorCode.OCF_ERR_WRITE_CACHE
        else:
            assert status == 0

        if not error_triggered:
            break

        # disable error injection and load the cache
        device.disarm()
        cache = None

        assert core_device.get_bytes()[io_offset] == Volume.VOLUME_POISON

        cache = Cache.load_from_device(device, open_cores=False)
        stats = cache.get_stats()
        if stats["conf"]["core_count"] == 1:
            assert stats["usage"]["occupancy"]["value"] == 1
            core = Core(device=core_device, try_add=True)
            cache.add_core(core)
            assert ocf_read(cache, core, io_offset) == 0xAA

        cache.stop()

        # advance error injection point
        error_io_seq_no += 1


@pytest.mark.security
def test_surprise_shutdown_cache_reinit(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))

    error_io = {IoDir.WRITE: 0}

    io_offset = mngmt_op_surprise_shutdown_test_io_offset

    error_triggered = True
    while error_triggered:
        # Start cache device without error injection
        device = ErrorDevice(
            mngmt_op_surprise_shutdown_test_cache_size, error_seq_no=error_io, armed=False
        )

        # start WB
        cache = Cache.start_on_device(device, cache_mode=CacheMode.WB)
        core = Core(device=core_device, try_add=False)
        cache.add_core(core)

        # insert dirty cacheline
        ocf_write(cache, core, 0xAA, io_offset)

        cache.stop()

        assert core_device.get_bytes()[io_offset] == Volume.VOLUME_POISON

        # start error injection
        device.arm()

        # power failure during cache re-initialization
        try:
            # sets force = True by default
            cache = Cache.start_on_device(device, cache_mode=CacheMode.WB)
            status = OcfErrorCode.OCF_OK
        except OcfError as ex:
            status = ex.error_code
            cache = None

        error_triggered = device.error_triggered()
        assert error_triggered == (status == OcfErrorCode.OCF_ERR_WRITE_CACHE)

        if cache:
            with pytest.raises(OcfError) as ex:
                cache.stop()
            assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE

        device.disarm()

        cache = Cache.load_from_device(device)

        stats = cache.get_stats()
        if stats["conf"]["core_count"] == 0:
            cache.add_core(core)
            assert ocf_read(cache, core, io_offset) == Volume.VOLUME_POISON

        cache.stop()

        error_io[IoDir.WRITE] += 1


def _test_surprise_shutdown_mngmt_generic(pyocf_ctx, func):
    core_device = Volume(S.from_MiB(10))
    core = Core(device=core_device, try_add=False)

    def prepare(cache):
        cache.add_core(core)

    def test(cache):
        func(cache, core)
        cache.save()

    mngmt_op_surprise_shutdown_test(pyocf_ctx, test, prepare, None)


@pytest.mark.security
def test_surprise_shutdown_change_cache_mode(pyocf_ctx):
    _test_surprise_shutdown_mngmt_generic(
        pyocf_ctx, lambda cache, core: cache.change_cache_mode(CacheMode.WT)
    )


@pytest.mark.security
def test_surprise_shutdown_set_cleaning_policy(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))
    core = Core(device=core_device, try_add=False)

    for c1 in CleaningPolicy:
        for c2 in CleaningPolicy:

            def prepare(cache):
                cache.add_core(core)
                cache.set_cleaning_policy(c1)
                cache.save()

            def test(cache):
                cache.set_cleaning_policy(c2)
                cache.save()

            mngmt_op_surprise_shutdown_test(pyocf_ctx, test, prepare, None)


@pytest.mark.security
def test_surprise_shutdown_set_seq_cut_off_policy(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))
    core = Core(device=core_device, try_add=False)

    for s1 in SeqCutOffPolicy:
        for s2 in SeqCutOffPolicy:

            def prepare(cache):
                cache.add_core(core)
                cache.set_seq_cut_off_policy(s1)
                cache.save()

            def test(cache):
                cache.set_seq_cut_off_policy(s2)
                cache.save()

            mngmt_op_surprise_shutdown_test(pyocf_ctx, test, prepare, None)


@pytest.mark.security
def test_surprise_shutdown_set_seq_cut_off_promotion(pyocf_ctx):
    _test_surprise_shutdown_mngmt_generic(
        pyocf_ctx, lambda cache, core: cache.set_seq_cut_off_promotion(256)
    )


@pytest.mark.security
def test_surprise_shutdown_set_seq_cut_off_threshold(pyocf_ctx):
    _test_surprise_shutdown_mngmt_generic(
        pyocf_ctx, lambda cache, core: cache.set_seq_cut_off_threshold(S.from_MiB(2).B)
    )


@pytest.mark.security
def test_surprise_shutdown_set_cleaning_policy_param(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))
    core = Core(device=core_device, try_add=False)

    for pol in CleaningPolicy:
        if pol == CleaningPolicy.NOP:
            continue
        if pol == CleaningPolicy.ALRU:
            params = AlruParams
        elif pol == CleaningPolicy.ACP:
            params = AcpParams
        else:
            # add handler for new policy here
            assert False

        for p in params:

            def prepare(cache):
                cache.add_core(core)
                cache.set_cleaning_policy(pol)
                cache.save()

            def test(cache):
                val = None
                if pol == CleaningPolicy.ACP:
                    if p == AcpParams.WAKE_UP_TIME:
                        val = 5000
                    elif p == AcpParams.FLUSH_MAX_BUFFERS:
                        val = 5000
                    else:
                        # add handler for new param here
                        assert False
                elif pol == CleaningPolicy.ALRU:
                    if p == AlruParams.WAKE_UP_TIME:
                        val = 2000
                    elif p == AlruParams.STALE_BUFFER_TIME:
                        val = 2000
                    elif p == AlruParams.FLUSH_MAX_BUFFERS:
                        val = 5000
                    elif p == AlruParams.ACTIVITY_THRESHOLD:
                        val = 500000
                    else:
                        # add handler for new param here
                        assert False
                cache.set_cleaning_policy_param(pol, p, val)
                cache.save()

            mngmt_op_surprise_shutdown_test(pyocf_ctx, test, prepare, None)


@pytest.mark.security
def test_surprise_shutdown_set_promotion_policy(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))
    core = Core(device=core_device, try_add=False)

    for pp1 in PromotionPolicy:
        for pp2 in PromotionPolicy:

            def prepare(cache):
                cache.add_core(core)
                cache.set_promotion_policy(pp1)
                cache.save()

            def test(cache):
                cache.set_promotion_policy(pp2)
                cache.save()

            print(f"setting PP to {pp2}")
            mngmt_op_surprise_shutdown_test(pyocf_ctx, test, prepare, None)


@pytest.mark.security
def test_surprise_shutdown_set_promotion_policy_param(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))
    core = Core(device=core_device, try_add=False)

    for pp in PromotionPolicy:
        if pp == PromotionPolicy.ALWAYS:
            continue
        if pp == PromotionPolicy.NHIT:
            params = NhitParams
        else:
            # add handler for new policy here
            assert False

        for p in params:

            def prepare(cache):
                cache.add_core(core)
                cache.set_promotion_policy(pp)
                cache.save()

            def test(cache):
                val = None
                if pp == PromotionPolicy.NHIT:
                    if p == NhitParams.INSERTION_THRESHOLD:
                        val = 500
                    elif p == NhitParams.TRIGGER_THRESHOLD:
                        val = 50
                    else:
                        # add handler for new param here
                        assert False
                cache.set_promotion_policy_param(pp, p, val)
                cache.save()

            mngmt_op_surprise_shutdown_test(pyocf_ctx, test, prepare, None)


@pytest.mark.security
def test_surprise_shutdown_set_io_class_config(pyocf_ctx):
    core_device = Volume(S.from_MiB(10))
    core = Core(device=core_device, try_add=False)

    class_range = range(0, IoClassesInfo.MAX_IO_CLASSES)
    old_ioclass = [
        {
            "_class_id": i,
            "_name": f"old_{i}" if i > 0 else "unclassified",
            "_max_size": i,
            "_priority": i,
            "_cache_mode": int(CacheMode.WB),
        }
        for i in range(IoClassesInfo.MAX_IO_CLASSES)
    ]
    new_ioclass = [
        {
            "_class_id": i,
            "_name": f"new_{i}" if i > 0 else "unclassified",
            "_max_size": 2 * i,
            "_priority": 2 * i,
            "_cache_mode": int(CacheMode.WT),
        }
        for i in range(IoClassesInfo.MAX_IO_CLASSES)
    ]
    keys = old_ioclass[0].keys()

    def set_io_class_info(cache, desc):
        ioclasses_info = IoClassesInfo()
        for i in range(IoClassesInfo.MAX_IO_CLASSES):
            ioclasses_info._config[i]._class_id = i
            ioclasses_info._config[i]._name = desc[i]["_name"].encode("utf-8")
            ioclasses_info._config[i]._priority = desc[i]["_priority"]
            ioclasses_info._config[i]._cache_mode = desc[i]["_cache_mode"]
            ioclasses_info._config[i]._max_size = desc[i]["_max_size"]
        OcfLib.getInstance().ocf_mngt_cache_io_classes_configure(
            cache, byref(ioclasses_info)
        )

    def prepare(cache):
        cache.add_core(core)
        set_io_class_info(cache, old_ioclass)
        cache.save()

    def test(cache):
        set_io_class_info(cache, new_ioclass)
        cache.save()

    def check(cache, error_triggered):
        curr_ioclass = [
            {k: info[k] for k in keys}
            for info in [cache.get_partition_info(i) for i in class_range]
        ]
        assert curr_ioclass == old_ioclass or curr_ioclass == new_ioclass

    mngmt_op_surprise_shutdown_test(pyocf_ctx, test, prepare, check)
