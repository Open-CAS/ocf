# Copyright(c) 2021-2022 Intel Corporation
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

from pyocf.types.ctx import OcfCtx
from pyocf.types.data import Data
from pyocf.types.core import Core
from pyocf.types.volume import ErrorDevice, RamVolume, VOLUME_POISON
from pyocf.types.volume_core import CoreVolume
from pyocf.types.volume_cache import CacheVolume
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

mngmt_op_surprise_shutdown_test_cache_size = S.from_MiB(40)
mngmt_op_surprise_shutdown_test_io_offset = S.from_MiB(4).B


def ocf_write(vol, queue, val, offset):
    data = Data.from_bytes(bytes([val] * 512))
    comp = OcfCompletion([("error", c_int)])
    io = vol.new_io(queue, offset, 512, IoDir.WRITE, 0, 0)
    io.set_data(data)
    io.callback = comp.callback
    io.submit()
    comp.wait()


def ocf_read(vol, queue, offset):
    data = Data(byte_count=512)
    comp = OcfCompletion([("error", c_int)])
    io = vol.new_io(queue, offset, 512, IoDir.READ, 0, 0)
    io.set_data(data)
    io.callback = comp.callback
    io.submit()
    comp.wait()
    return data.get_bytes()[0]


def prepare_failover(pyocf_2_ctx, cache_backend_vol, error_io_seq_no):
    ctx1 = pyocf_2_ctx[0]
    ctx2 = pyocf_2_ctx[1]

    cache2 = Cache(owner=ctx2)
    cache2.start_cache()
    cache2.standby_attach(cache_backend_vol)
    cache2_exp_obj_vol = CacheVolume(cache2, open=True)

    error_io = {IoDir.WRITE: error_io_seq_no}

    # TODO: Adjust tests to work with error injection for flushes and discards (data_only=False
    # below). Currently the test fails with data_only=False as it assumes metadata is not updated
    # if error had been injected, which is not true in case of error in flush.
    err_vol = ErrorDevice(cache2_exp_obj_vol, error_seq_no=error_io, data_only=True, armed=False)
    cache = Cache.start_on_device(err_vol, cache_mode=CacheMode.WB, owner=ctx1)

    return cache, cache2, err_vol


def prepare_normal(pyocf_2_ctx, cache_backend_vol, error_io_seq_no):
    ctx1 = pyocf_2_ctx[0]

    error_io = {IoDir.WRITE: error_io_seq_no}

    err_vol = ErrorDevice(cache_backend_vol, error_seq_no=error_io, data_only=True, armed=False)
    cache = Cache.start_on_device(err_vol, cache_mode=CacheMode.WB, owner=ctx1)

    return cache, err_vol


def mngmt_op_surprise_shutdown_test(
    pyocf_2_ctx, failover, mngt_func, prepare_func, consistency_check_func
):
    error_triggered = True
    error_io_seq_no = 0

    while error_triggered:
        cache_backend_vol = RamVolume(mngmt_op_surprise_shutdown_test_cache_size)

        if failover:
            cache, cache2, err_vol = prepare_failover(
                pyocf_2_ctx, cache_backend_vol, error_io_seq_no
            )
        else:
            cache, err_vol = prepare_normal(pyocf_2_ctx, cache_backend_vol, error_io_seq_no)

        if prepare_func:
            prepare_func(cache)

        # make sure cache state is persistent
        cache.save()

        # initiate error injection starting at write no @error_io_seq_no
        err_vol.arm()

        # call tested management function
        try:
            mngt_func(cache)
            status = OcfErrorCode.OCF_OK
        except OcfError as ex:
            status = ex.error_code

        # if error was injected we expect mngmt op error
        error_triggered = err_vol.error_triggered()
        assert error_triggered == (status != 0)
        if error_triggered:
            assert status == OcfErrorCode.OCF_ERR_WRITE_CACHE or status == OcfErrorCode.OCF_ERR_IO

        # stop cache with error injection still on
        with pytest.raises(OcfError) as ex:
            cache.stop()
            cache = None
        assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE

        # discard error volume
        err_vol.disarm()

        if failover:
            cache2.standby_detach()
            cache2.standby_activate(cache_backend_vol, open_cores=True)
            cache = cache2
        else:
            cache = Cache.load_from_device(err_vol, open_cores=True)

        # run consistency check
        if consistency_check_func is not None:
            consistency_check_func(cache, error_triggered)

        # stop the cache
        cache.stop()

        # advance error injection point
        error_io_seq_no += 1


# power failure during core insert
@pytest.mark.security
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_add_core(pyocf_2_ctx, failover):
    core_device = RamVolume(S.from_MiB(10))

    def check_core(cache, error_triggered):
        stats = cache.get_stats()
        assert stats["conf"]["core_count"] == (0 if error_triggered else 1)

    def tested_func(cache):
        core = Core(device=core_device)
        cache.add_core(core)

    def check_func(cache, error_triggered):
        check_core(cache, error_triggered)

    mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, tested_func, None, check_func)


# power failure during core removal
@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_remove_core(pyocf_2_ctx, failover):
    core_device = RamVolume(S.from_MiB(10))
    core = Core.using_device(core_device)

    def prepare_func(cache):
        cache.add_core(core)

    def tested_func(cache):
        cache.remove_core(core)

    def check_func(cache, error_triggered):
        stats = cache.get_stats()
        assert stats["conf"]["core_count"] == (1 if error_triggered else 0)

    mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, tested_func, prepare_func, check_func)


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_remove_core_with_data(pyocf_2_ctx, failover):
    io_offset = mngmt_op_surprise_shutdown_test_io_offset
    core_device = RamVolume(S.from_MiB(10))
    core = Core.using_device(core_device, name="core1")

    def prepare_func(cache):
        cache.add_core(core)
        vol = CoreVolume(core, open=True)
        ocf_write(vol, cache.get_default_queue(), 0xAA, io_offset)

    def tested_func(cache):
        cache.flush()
        cache.remove_core(core)

    def check_func(cache, error_triggered):
        stats = cache.get_stats()
        if stats["conf"]["core_count"] == 0:
            assert core_device.get_bytes()[io_offset] == 0xAA
        else:
            core = cache.get_core_by_name("core1")
            vol = CoreVolume(core, open=True)
            assert ocf_read(vol, cache.get_default_queue(), io_offset) == 0xAA

    mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, tested_func, prepare_func, check_func)


# power failure during core add after previous core removed
@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_swap_core(pyocf_2_ctx, failover):
    core_device_1 = RamVolume(S.from_MiB(10), uuid="dev1")
    core_device_2 = RamVolume(S.from_MiB(10), uuid="dev2")
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

        with pytest.raises(OcfError):
            core1 = cache.get_core_by_name("core1")

        if error_triggered:
            with pytest.raises(OcfError):
                core2 = cache.get_core_by_name("core2")
        else:
            core2 = cache.get_core_by_name("core2")
            assert core2.device.uuid == "dev2"

    mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, tested_func, prepare, check_func)


# power failure during core add after previous core removed
@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_swap_core_with_data(pyocf_2_ctx, failover):
    core_device_1 = RamVolume(S.from_MiB(10), uuid="dev1")
    core_device_2 = RamVolume(S.from_MiB(10), uuid="dev2")
    core1 = Core.using_device(core_device_1, name="core1")
    core2 = Core.using_device(core_device_2, name="core2")

    def prepare(cache):
        cache.add_core(core1)
        vol = CoreVolume(core1, open=True)
        cache.save()
        ocf_write(
            vol, cache.get_default_queue(), 0xAA, mngmt_op_surprise_shutdown_test_io_offset,
        )
        cache.remove_core(core1)
        cache.save()

    def tested_func(cache):
        cache.add_core(core2)

    def check_func(cache, error_triggered):
        stats = cache.get_stats()
        assert stats["conf"]["core_count"] == (0 if error_triggered else 1)

        with pytest.raises(OcfError):
            core1 = cache.get_core_by_name("core1")

        core2 = None
        if error_triggered:
            with pytest.raises(OcfError):
                core2 = cache.get_core_by_name("core2")
        else:
            core2 = cache.get_core_by_name("core2")

        if core2 is not None:
            vol2 = CoreVolume(core2, open=True)
            assert core2.device.uuid == "dev2"
            assert (
                ocf_read(
                    vol2, cache.get_default_queue(), mngmt_op_surprise_shutdown_test_io_offset,
                )
                == VOLUME_POISON
            )

    mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, tested_func, prepare, check_func)


# make sure there are no crashes when cache start is interrupted
@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_start_cache(pyocf_2_ctx, failover):
    ctx1 = pyocf_2_ctx[0]
    ctx2 = pyocf_2_ctx[1]

    error_triggered = True
    error_io_seq_no = 0

    while error_triggered:
        # Start cache device without error injection
        error_io = {IoDir.WRITE: error_io_seq_no}

        ramdisk = RamVolume(mngmt_op_surprise_shutdown_test_cache_size)

        if failover:
            cache2 = Cache(owner=ctx2)
            cache2.start_cache()
            cache2.standby_attach(ramdisk)
            cache2_exp_obj_vol = CacheVolume(cache2, open=True)
            err_device = ErrorDevice(
                cache2_exp_obj_vol, error_seq_no=error_io, data_only=True, armed=True
            )
        else:
            err_device = ErrorDevice(ramdisk, error_seq_no=error_io, data_only=True, armed=True)

        # call tested management function
        try:
            cache = Cache.start_on_device(err_device, cache_mode=CacheMode.WB)
            status = OcfErrorCode.OCF_OK
        except OcfError as ex:
            status = ex.error_code

        # if error was injected we expect mngmt op error
        error_triggered = err_device.error_triggered()
        assert error_triggered == (status != 0)

        if not error_triggered:
            # stop cache with error injection still on
            with pytest.raises(OcfError) as ex:
                cache.stop()
            assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE
            break

        # disable error injection and load the cache
        err_device.disarm()
        cache = None

        if failover:
            try:
                cache2.standby_detach()
                cache2.standby_activate(ramdisk, open_cores=True)
                cache = cache2
            except OcfError:
                cache2.stop()
                cache2 = None
                cache = None
        else:
            try:
                cache = Cache.load_from_device(err_device, open_cores=True)
            except OcfError:
                cache = None

        if cache is not None:
            cache.stop()
            cache = None

        # advance error injection point
        error_io_seq_no += 1


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_stop_cache(pyocf_2_ctx, failover):
    core_device = RamVolume(S.from_MiB(10))
    error_triggered = True
    error_io_seq_no = 0
    io_offset = mngmt_op_surprise_shutdown_test_io_offset

    while error_triggered:
        # Start cache device without error injection
        ramdisk = RamVolume(mngmt_op_surprise_shutdown_test_cache_size)

        if failover:
            cache, cache2, device = prepare_failover(pyocf_2_ctx, ramdisk, error_io_seq_no)
        else:
            cache, device = prepare_normal(pyocf_2_ctx, ramdisk, error_io_seq_no)

        core = Core(device=core_device)
        cache.add_core(core)
        vol = CoreVolume(core, open=True)
        ocf_write(vol, cache.get_default_queue(), 0xAA, io_offset)

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
            assert status == OcfErrorCode.OCF_OK

        if not error_triggered:
            break

        # disable error injection and load the cache
        device.disarm()
        cache = None

        assert core_device.get_bytes()[io_offset] == VOLUME_POISON

        if failover:
            cache2.standby_detach()
            cache2.standby_activate(ramdisk, open_cores=False)
            cache = cache2
        else:
            cache = Cache.load_from_device(device, open_cores=False)

        stats = cache.get_stats()
        if stats["conf"]["core_count"] == 1:
            assert stats["usage"]["occupancy"]["value"] == 1
            core = Core(device=core_device)
            cache.add_core(core, try_add=True)
            vol = CoreVolume(core, open=True)
            assert ocf_read(vol, cache.get_default_queue(), io_offset) == 0xAA

        cache.stop()

        # advance error injection point
        error_io_seq_no += 1


@pytest.mark.security
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_cache_reinit(pyocf_2_ctx, failover):
    core_device = RamVolume(S.from_MiB(10))

    error_io_seq_no = 0

    io_offset = mngmt_op_surprise_shutdown_test_io_offset

    error_triggered = True
    while error_triggered:
        ramdisk = RamVolume(mngmt_op_surprise_shutdown_test_cache_size)

        if failover:
            cache, cache2, device = prepare_failover(pyocf_2_ctx, ramdisk, error_io_seq_no)
        else:
            cache, device = prepare_normal(pyocf_2_ctx, ramdisk, error_io_seq_no)

        core = Core(device=core_device)
        cache.add_core(core)
        vol = CoreVolume(core, open=True)
        queue = cache.get_default_queue()

        # insert dirty cacheline
        ocf_write(vol, queue, 0xAA, io_offset)

        cache.stop()
        cache = None

        assert core_device.get_bytes()[io_offset] == VOLUME_POISON

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

        cache = None
        status = OcfErrorCode.OCF_OK

        if failover:
            try:
                cache2.standby_detach()
                cache2.standby_activate(ramdisk, open_cores=True)
                cache = cache2
            except OcfError as ex:
                cache2.stop()
                cache2 = None
                status = ex.error_code
        else:
            try:
                cache = Cache.load_from_device(device, open_cores=True)
            except OcfError as ex:
                status = ex.error_code

        if not cache:
            assert status == OcfErrorCode.OCF_ERR_NO_METADATA
        else:
            stats = cache.get_stats()
            if stats["conf"]["core_count"] == 0:
                assert stats["usage"]["occupancy"]["value"] == 0
                cache.add_core(core)
                vol = CoreVolume(core, open=True)
                assert ocf_read(vol, cache.get_default_queue(), io_offset) == VOLUME_POISON

            cache.stop()
            cache = None

        error_io_seq_no += 1


def _test_surprise_shutdown_mngmt_generic(pyocf_2_ctx, failover, func):
    core_device = RamVolume(S.from_MiB(10))
    core = Core(device=core_device)

    def prepare(cache):
        cache.add_core(core)

    def test(cache):
        func(cache, core)
        cache.save()

    mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, test, prepare, None)


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_change_cache_mode(pyocf_2_ctx, failover):
    _test_surprise_shutdown_mngmt_generic(
        pyocf_2_ctx, failover, lambda cache, core: cache.change_cache_mode(CacheMode.WT)
    )


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
@pytest.mark.parametrize("start_clp", CleaningPolicy)
@pytest.mark.parametrize("end_clp", CleaningPolicy)
def test_surprise_shutdown_set_cleaning_policy(pyocf_2_ctx, failover, start_clp, end_clp):
    core_device = RamVolume(S.from_MiB(10))
    core = Core(device=core_device)

    def prepare(cache):
        cache.add_core(core)
        cache.set_cleaning_policy(start_clp)
        cache.save()

    def test(cache):
        cache.set_cleaning_policy(end_clp)
        cache.save()

    mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, test, prepare, None)


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
@pytest.mark.parametrize("start_scp", SeqCutOffPolicy)
@pytest.mark.parametrize("end_scp", SeqCutOffPolicy)
def test_surprise_shutdown_set_seq_cut_off_policy(pyocf_2_ctx, failover, start_scp, end_scp):
    core_device = RamVolume(S.from_MiB(10))
    core = Core(device=core_device)

    def prepare(cache):
        cache.add_core(core)
        cache.set_seq_cut_off_policy(start_scp)
        cache.save()

    def test(cache):
        cache.set_seq_cut_off_policy(end_scp)
        cache.save()

    mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, test, prepare, None)


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_set_seq_cut_off_promotion(pyocf_2_ctx, failover):
    _test_surprise_shutdown_mngmt_generic(
        pyocf_2_ctx, failover, lambda cache, core: cache.set_seq_cut_off_promotion(256)
    )


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_set_seq_cut_off_threshold(pyocf_2_ctx, failover):
    _test_surprise_shutdown_mngmt_generic(
        pyocf_2_ctx, failover, lambda cache, core: cache.set_seq_cut_off_threshold(S.from_MiB(2).B),
    )


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
@pytest.mark.parametrize("clp", [c for c in CleaningPolicy if c != CleaningPolicy.NOP])
def test_surprise_shutdown_set_cleaning_policy_param(pyocf_2_ctx, failover, clp):
    core_device = RamVolume(S.from_MiB(10))
    core = Core(device=core_device)

    if clp == CleaningPolicy.ALRU:
        params = AlruParams
    elif clp == CleaningPolicy.ACP:
        params = AcpParams
    else:
        # add handler for new policy here
        assert False

    for p in params:

        def prepare(cache):
            cache.add_core(core)
            cache.set_cleaning_policy(clp)
            cache.save()

        def test(cache):
            val = None
            if clp == CleaningPolicy.ACP:
                if p == AcpParams.WAKE_UP_TIME:
                    val = 5000
                elif p == AcpParams.FLUSH_MAX_BUFFERS:
                    val = 5000
                else:
                    # add handler for new param here
                    assert False
            elif clp == CleaningPolicy.ALRU:
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
            cache.set_cleaning_policy_param(clp, p, val)
            cache.save()

        mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, test, prepare, None)


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
@pytest.mark.parametrize("start_pp", PromotionPolicy)
@pytest.mark.parametrize("end_pp", PromotionPolicy)
def test_surprise_shutdown_set_promotion_policy(pyocf_2_ctx, failover, start_pp, end_pp):
    core_device = RamVolume(S.from_MiB(10))
    core = Core(device=core_device)

    def prepare(cache):
        cache.add_core(core)
        cache.set_promotion_policy(start_pp)
        cache.save()

    def test(cache):
        cache.set_promotion_policy(end_pp)
        cache.save()

    mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, test, prepare, None)


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
@pytest.mark.parametrize("pp", PromotionPolicy)
def test_surprise_shutdown_set_promotion_policy_param(pyocf_2_ctx, failover, pp):
    core_device = RamVolume(S.from_MiB(10))
    core = Core(device=core_device)

    if pp == PromotionPolicy.ALWAYS:
        return
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

        mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, test, prepare, None)


@pytest.mark.security
@pytest.mark.long
@pytest.mark.parametrize("failover", [False, True])
def test_surprise_shutdown_set_io_class_config(pyocf_2_ctx, failover):
    core_device = RamVolume(S.from_MiB(10))
    core = Core(device=core_device)

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
        OcfLib.getInstance().ocf_mngt_cache_io_classes_configure(cache, byref(ioclasses_info))

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

    mngmt_op_surprise_shutdown_test(pyocf_2_ctx, failover, test, prepare, check)


@pytest.mark.security
@pytest.mark.long
def test_surprise_shutdown_standby_activate(pyocf_ctx):
    """ 1. start active cache
        2. add core, insert data
        3. stop
        4. load standby
        5. detach
        6. activate <- with I/O error injection
        7. standby load
        8. verify consistency
    """
    io_offset = mngmt_op_surprise_shutdown_test_io_offset
    error_triggered = True
    error_io_seq_no = 0

    while error_triggered:
        # Start cache device without error injection
        error_io = {IoDir.WRITE: error_io_seq_no}
        ramdisk = RamVolume(mngmt_op_surprise_shutdown_test_cache_size)
        device = ErrorDevice(ramdisk, error_seq_no=error_io, data_only=True, rmed=False)
        core_device = RamVolume(S.from_MiB(10))

        device.disarm()

        # Add a core device and provide a few dirty blocks
        cache = Cache.start_on_device(device, cache_mode=CacheMode.WB)
        core = Core(device=core_device)
        cache.add_core(core)
        vol = CoreVolume(core, open=True)
        ocf_write(vol, cache.get_default_queue(), 0xAA, io_offset)
        original_dirty_blocks = cache.get_stats()["usage"]["dirty"]
        cache.stop()

        # Preapre a passive instance
        cache = Cache(owner=OcfCtx.get_default())
        cache.start_cache()
        cache.standby_load(device)
        cache.standby_detach()

        device.arm()

        # If the activate failes, cache should be rollbacked into the passive state
        try:
            cache.standby_activate(device)
            status = OcfErrorCode.OCF_OK
        except OcfError as ex:
            status = ex.error_code
            cache.stop()

        # If error was injected we expect mngmt op error
        error_triggered = device.error_triggered()
        assert error_triggered == (status != 0)

        # Activate succeeded but error injection is still enabled
        if not error_triggered:
            with pytest.raises(OcfError) as ex:
                cache.stop()

        # Disable error injection and activate cache
        device.disarm()
        cache = None

        cache = Cache(owner=OcfCtx.get_default())
        cache.start_cache()
        cache.standby_load(device)
        cache.standby_detach()
        cache.standby_activate(device, open_cores=False)

        assert cache.get_stats()["conf"]["core_count"] == 1
        assert original_dirty_blocks == cache.get_stats()["usage"]["dirty"]

        core = Core(device=core_device)
        cache.add_core(core, try_add=True)
        vol = CoreVolume(core, open=True)
        assert ocf_read(vol, cache.get_default_queue(), io_offset) == 0xAA

        cache.stop()

        # advance error injection point
        error_io_seq_no += 1


@pytest.mark.security
@pytest.mark.long
def test_surprise_shutdown_standby_init_clean(pyocf_ctx):
    """ interrupted standby init on an empty volume """
    error_triggered = True
    error_io_seq_no = 0

    while error_triggered:
        # Start cache device without error injection
        error_io = {IoDir.WRITE: error_io_seq_no}
        ramdisk = RamVolume(mngmt_op_surprise_shutdown_test_cache_size)
        device = ErrorDevice(ramdisk, error_seq_no=error_io, data_only=True, armed=True)

        cache = Cache(owner=OcfCtx.get_default())
        cache.start_cache()

        try:
            cache.standby_attach(device)
            status = OcfErrorCode.OCF_OK
        except OcfError as ex:
            status = ex.error_code
            cache.stop()

        # if error was injected we expect mngmt op error
        error_triggered = device.error_triggered()
        assert error_triggered == (status != 0)

        if not error_triggered:
            # stop cache with error injection still on - expect no error in standby
            # as no writes go to the disk
            cache.stop()
            break

        # disable error injection and load the cache
        device.disarm()
        cache = None

        cache = Cache(owner=OcfCtx.get_default())
        cache.start_cache()

        with pytest.raises(OcfError) as ex:
            cache.standby_load(device)
            assert ex.value.error_code == OcfErrorCode.OCF_ERR_NO_METADATA

        cache.stop()

        # advance error injection point
        error_io_seq_no += 1


@pytest.mark.security
@pytest.mark.long
def test_surprise_shutdown_standby_init_force_1(pyocf_ctx):
    """ 1. start active
        2. add core, insert cacheline
        3. stop cache
        4. standby attach force = 1 <- with I/O injection
        5. standby load
        6. activate
        7. verify consistency: either no metadata, empty cache or cacheline still inserted
    """
    core_device = RamVolume(S.from_MiB(10))
    io_offset = mngmt_op_surprise_shutdown_test_io_offset

    error_triggered = True
    error_io_seq_no = 0

    while error_triggered:
        # Start cache device without error injection
        error_io = {IoDir.WRITE: error_io_seq_no}
        ramdisk = RamVolume(mngmt_op_surprise_shutdown_test_cache_size)
        device = ErrorDevice(ramdisk, error_seq_no=error_io, data_only=True, armed=False)

        # start and stop cache with cacheline inserted
        cache = Cache.start_on_device(device, cache_mode=CacheMode.WB)
        core = Core(device=core_device)
        cache.add_core(core)
        vol = CoreVolume(core, open=True)
        ocf_write(vol, cache.get_default_queue(), 0xAA, io_offset)
        original_dirty_blocks = cache.get_stats()["usage"]["dirty"]
        cache.stop()

        cache = Cache(owner=OcfCtx.get_default())
        cache.start_cache()

        device.arm()

        # attempt to reinitialize standby cache with erorr injection
        try:
            cache.standby_attach(device, force=True)
            status = OcfErrorCode.OCF_OK
        except OcfError as ex:
            status = ex.error_code

        # if error was injected we expect mngmt op error
        error_triggered = device.error_triggered()
        assert error_triggered == (status == OcfErrorCode.OCF_ERR_WRITE_CACHE)

        # stop cache with error injection still on
        # expect no error when stoping standby or detached cache
        cache.stop()
        cache = None

        # disable error injection and load the cache
        device.disarm()

        cache = Cache(owner=OcfCtx.get_default())
        cache.start_cache()

        # standby load
        try:
            cache.standby_load(device)
            cache.standby_detach()
            cache.standby_activate(device, open_cores=False)
            status = OcfErrorCode.OCF_OK
        except OcfError as ex:
            status = ex.error_code

        if status != OcfErrorCode.OCF_OK:
            assert status == OcfErrorCode.OCF_ERR_NO_METADATA
        else:
            stats = cache.get_stats()
            if stats["conf"]["core_count"] == 1:
                assert original_dirty_blocks == stats["usage"]["dirty"]
                core = Core(device=core_device)
                cache.add_core(core, try_add=True)
                vol = CoreVolume(core, open=True)
                assert ocf_read(vol, cache.get_default_queue(), io_offset) == 0xAA
            else:
                assert stats["usage"]["occupancy"]["value"] == 0
                assert stats["usage"]["dirty"]["value"] == 0
                core = Core(device=core_device)
                cache.add_core(core)
                vol = CoreVolume(core, open=True)
                assert ocf_read(vol, cache.get_default_queue(), io_offset) == VOLUME_POISON

        cache.stop()

        error_io_seq_no += 1


@pytest.mark.security
@pytest.mark.long
def test_surprise_shutdown_standby_init_force_2(pyocf_ctx):
    """ 1. start active
        2. add core, insert cacheline
        3. stop cache
        4. standby attach force = 1 <- with I/O injection
        5. load cache (standard load)
        6. verify consistency: either no metadata, empty cache or cacheline still inserted
    """
    core_device = RamVolume(S.from_MiB(10))
    io_offset = mngmt_op_surprise_shutdown_test_io_offset

    error_triggered = True
    error_io_seq_no = 0

    while error_triggered:
        # Start cache device without error injection
        error_io = {IoDir.WRITE: error_io_seq_no}
        ramdisk = RamVolume(mngmt_op_surprise_shutdown_test_cache_size)
        device = ErrorDevice(ramdisk, error_seq_no=error_io, data_only=True, armed=False)

        # start and stop cache with cacheline inserted
        cache = Cache.start_on_device(device, cache_mode=CacheMode.WB)
        core = Core(device=core_device)
        cache.add_core(core)
        vol = CoreVolume(core, open=True)
        ocf_write(vol, cache.get_default_queue(), 0xAA, io_offset)
        original_dirty_blocks = cache.get_stats()["usage"]["dirty"]
        cache.stop()

        cache = Cache(owner=OcfCtx.get_default())
        cache.start_cache()

        device.arm()

        # attempt to reinitialize standby cache with erorr injection
        try:
            cache.standby_attach(device, force=True)
            status = OcfErrorCode.OCF_OK
        except OcfError as ex:
            status = ex.error_code

        # if error was injected we expect mngmt op error
        error_triggered = device.error_triggered()
        assert error_triggered == (status == OcfErrorCode.OCF_ERR_WRITE_CACHE)

        # stop cache with error injection still on
        # expect no error when stoping standby or detached cache
        cache.stop()
        cache = None

        # disable error injection and load the cache
        device.disarm()

        # standard load
        try:
            cache = Cache.load_from_device(device, open_cores=False)
            status = OcfErrorCode.OCF_OK
        except OcfError as ex:
            status = ex.error_code

        if status != OcfErrorCode.OCF_OK:
            assert status == OcfErrorCode.OCF_ERR_NO_METADATA
        else:
            stats = cache.get_stats()
            if stats["conf"]["core_count"] == 1:
                assert original_dirty_blocks == stats["usage"]["dirty"]
                core = Core(device=core_device)
                cache.add_core(core, try_add=True)
                vol = CoreVolume(core, open=True)
                assert ocf_read(vol, cache.get_default_queue(), io_offset) == 0xAA
            else:
                assert stats["usage"]["occupancy"]["value"] == 0
                assert stats["usage"]["dirty"]["value"] == 0
                core = Core(device=core_device)
                cache.add_core(core)
                vol = CoreVolume(core, open=True)
                assert ocf_read(vol, cache.get_default_queue(), io_offset) == VOLUME_POISON

        if cache:
            cache.stop()
            cache = None

        error_io_seq_no += 1
