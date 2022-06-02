#
# Copyright(c) 2022-2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
import copy
from ctypes import c_int

from pyocf.types.cache import (
    Cache,
    CacheMode,
    MetadataLayout,
    CleaningPolicy,
)
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import Io, IoDir
from pyocf.types.volume import RamVolume, Volume
from pyocf.types.volume_cache import CacheVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.types.volume_replicated import ReplicatedVolume
from pyocf.types.shared import (
    OcfError,
    OcfErrorCode,
    OcfCompletion,
    CacheLines,
    CacheLineSize,
    SeqCutOffPolicy,
)
from pyocf.utils import Size
from pyocf.rio import Rio, ReadWrite


def test_standby_stop_closes_volume(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force=False)
    cache.stop()
    assert not vol.opened


def test_standby_stop_detached(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force=False)
    cache.standby_detach()
    assert not vol.opened
    cache.stop()


# verify that force flag is required to attach a standby instance
# on a volume where standby instance had previously been running
def test_standby_attach_force_after_standby(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force=False)
    cache.standby_detach()
    cache.stop()

    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    with pytest.raises(OcfError) as ex:
        cache.standby_attach(vol, force=False)
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_METADATA_FOUND

    cache.standby_attach(vol, force=True)


def test_standby_attach_force_after_active(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.attach_device(vol)
    cache.stop()
    assert not vol.opened

    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    with pytest.raises(OcfError) as ex:
        cache.standby_attach(vol, force=False)
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_METADATA_FOUND

    cache.standby_attach(vol, force=True)


# standby load from standby cache instance after clean shutdown
def test_standby_load_after_standby_clean_shutdown(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force=False)
    cache.stop()

    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()

    vol.reset_stats()
    cache.standby_load(vol, perform_test=False)
    assert vol.get_stats()[IoDir.WRITE] == 0

    cache.stop()


# standby load from active cache instance after clean shutdown
def test_standby_load_after_active_clean_shutdown(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.attach_device(vol, force=False)
    cache.stop()

    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()

    vol.reset_stats()
    cache.standby_load(vol, perform_test=False)
    assert vol.get_stats()[IoDir.WRITE] == 0


# standby load from active cache instance after clean shutdown
def test_standby_load_after_active_dirty_shutdown(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.attach_device(vol, force=False)
    vol.offline()
    with pytest.raises(OcfError) as ex:
        cache.stop()
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE
    vol.online()

    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    vol.reset_stats()
    cache.standby_load(vol, perform_test=False)
    assert vol.get_stats()[IoDir.WRITE] == 0

    cache.stop()


def test_standby_load_after_standby_dirty_shutdown(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force=False)
    vol.offline()
    cache.stop()

    vol.online()
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    vol.reset_stats()
    cache.standby_load(vol, perform_test=False)
    assert vol.get_stats()[IoDir.WRITE] == 0

    cache.stop()


def test_standby_load_after_standby_dirty_shutdown_with_vol_test(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol, force=False)
    vol.offline()
    cache.stop()

    vol.online()
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_load(vol)

    cache.stop()


def test_standby_activate_core_size_mismatch_after_active(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol = RamVolume(Size.from_MiB(150))
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.attach_device(vol, force=False)

    # prepare and stop cache instance with standard size core volume
    core_vol_uuid = str(id(cache))
    core_vol_size_initial = Size.from_MiB(150)
    core_vol = RamVolume(core_vol_size_initial, uuid=core_vol_uuid)
    core = Core(core_vol)
    cache.add_core(core)
    cache.stop()
    cache = None

    # resize core volume
    # TODO: how to avoid manually removing vol<->uuid mapping?
    del Volume._uuid_[core_vol.uuid]
    core_vol = None
    core_vol = RamVolume(2 * core_vol_size_initial, uuid=core_vol_uuid)

    # standby load on the volume
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_load(vol)
    cache.standby_detach()

    # first attempt to activate with size mismatch
    with pytest.raises(OcfError) as ex:
        cache.standby_activate(vol)
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_CORE_SIZE_MISMATCH

    # second attempt to activate with size mismatch
    with pytest.raises(OcfError) as ex:
        cache.standby_activate(vol)
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_CORE_SIZE_MISMATCH

    del Volume._uuid_[core_vol.uuid]
    core_vol = RamVolume(core_vol_size_initial, uuid=core_vol_uuid)

    # attempt to activate with fixed sizE
    cache.standby_activate(vol)

    cache.stop()


def test_standby_activate_core_size_mismatch(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    vol1 = RamVolume(Size.from_MiB(150), uuid="cv1")
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.attach_device(vol1, force=False)

    core_vol_uuid = str(id(cache))
    core_vol_size_initial = Size.from_MiB(150)
    core_vol = RamVolume(core_vol_size_initial, uuid=core_vol_uuid)
    core2_vol = RamVolume(core_vol_size_initial)
    core = Core(core_vol)
    core2 = Core(core2_vol, name="core2")
    cache.add_core(core)
    cache.add_core(core2)

    data = vol1.get_bytes()

    cache.stop()

    vol1 = None

    del Volume._uuid_[core_vol.uuid]
    core_vol = None

    vol2 = RamVolume(Size.from_MiB(150), uuid="cv2")
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_attach(vol2)
    cache_vol = CacheVolume(cache, open=True)

    write_vol(cache_vol, cache.get_default_queue(), data)

    core_vol = RamVolume(2 * core_vol_size_initial, uuid=core_vol_uuid)

    cache.standby_detach()

    # first attempt to activate with size mismatch
    with pytest.raises(OcfError) as ex:
        cache.standby_activate(vol2)
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_CORE_SIZE_MISMATCH

    # second attempt to activate with size mismatch
    with pytest.raises(OcfError) as ex:
        cache.standby_activate(vol2)
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_CORE_SIZE_MISMATCH

    del Volume._uuid_[core_vol.uuid]
    core_vol = None
    core_vol = RamVolume(core_vol_size_initial, uuid=core_vol_uuid)

    # attempt to activate with fixed sizE
    cache.standby_activate(vol2)

    cache.stop()


def test_failover_passive_first(pyocf_2_ctx):
    ctx1 = pyocf_2_ctx[0]
    ctx2 = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB

    prim_cache_backend_vol = RamVolume(Size.from_MiB(150))
    core_backend_vol = RamVolume(Size.from_MiB(1))
    sec_cache_backend_vol = RamVolume(Size.from_MiB(150))

    # passive cache with directly on ram disk
    cache2 = Cache(owner=ctx2, cache_mode=mode, cache_line_size=cls)
    cache2.start_cache()
    cache2.standby_attach(sec_cache_backend_vol)

    # volume replicating cache1 ramdisk writes to cache2 cache exported object
    cache2_exp_obj_vol = CacheVolume(cache2, open=True)
    cache1_cache_vol = ReplicatedVolume(prim_cache_backend_vol, cache2_exp_obj_vol)

    # active cache
    cache1 = Cache.start_on_device(cache1_cache_vol, ctx1, cache_mode=mode, cache_line_size=cls)
    core = Core(core_backend_vol)
    cache1.add_core(core)
    core_vol = CoreVolume(core, open=True)
    queue = cache1.get_default_queue()

    # some I/O
    r = (
        Rio()
        .target(core_vol)
        .njobs(1)
        .readwrite(ReadWrite.WRITE)
        .size(Size.from_MiB(1))
        .qd(1)
        .run([queue])
    )

    # capture checksum before simulated active host failure
    md5 = core_vol.md5()

    # offline primary cache volume and stop primary cache to simulate active host
    # failure
    cache1_cache_vol.offline()
    with pytest.raises(OcfError) as ex:
        cache1.stop()
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE

    # failover
    cache2.standby_detach()
    cache2.standby_activate(sec_cache_backend_vol, open_cores=False)

    # add core explicitly with "try_add" to workaround pyocf limitations
    core = Core(core_backend_vol)
    cache2.add_core(core, try_add=True)
    core_vol = CoreVolume(core, open=True)

    assert md5 == core_vol.md5()


def write_vol(vol, queue, data):
    data_size = len(data)
    subdata_size_max = int(Size.from_MiB(32))
    for offset in range(0, data_size, subdata_size_max):
        subdata_size = min(data_size - offset, subdata_size_max)
        subdata = Data.from_bytes(data, offset, subdata_size)
        comp = OcfCompletion([("error", c_int)])
        io = vol.new_io(queue, offset, subdata_size, IoDir.WRITE, 0, 0,)
        io.set_data(subdata)
        io.callback = comp.callback
        io.submit()
        comp.wait()


def test_failover_active_first(pyocf_2_ctx):
    ctx1 = pyocf_2_ctx[0]
    ctx2 = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB

    prim_cache_backend_vol = RamVolume(Size.from_MiB(150))
    core_backend_vol = RamVolume(Size.from_MiB(1))

    # active cache
    cache1 = Cache.start_on_device(
        prim_cache_backend_vol, ctx1, cache_mode=mode, cache_line_size=cls
    )
    core = Core(core_backend_vol)
    cache1.add_core(core)
    vol = CoreVolume(core, open=True)
    queue1 = cache1.get_default_queue()

    # some I/O
    r = (
        Rio()
        .target(vol)
        .njobs(1)
        .readwrite(ReadWrite.WRITE)
        .size(Size.from_MiB(1))
        .qd(1)
        .run([queue1])
    )

    # capture checksum before simulated active host failure
    data_md5 = vol.md5()

    prim_cache_backend_vol.offline()

    with pytest.raises(OcfError) as ex:
        cache1.stop()
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE

    # capture a copy of active cache instance data
    data = prim_cache_backend_vol.get_bytes()
    cache_md5 = prim_cache_backend_vol.md5()

    # setup standby cache
    sec_cache_backend_vol = RamVolume(Size.from_MiB(150))
    cache2 = Cache(owner=ctx2, cache_mode=mode, cache_line_size=cls)
    cache2.start_cache()
    cache2.standby_attach(sec_cache_backend_vol)
    vol2 = CacheVolume(cache2, open=True)
    queue = cache2.get_default_queue()

    # standby cache exported object volume
    cache2_exp_obj_vol = CacheVolume(cache2, open=True)

    # just to be sure
    assert sec_cache_backend_vol.get_bytes() != prim_cache_backend_vol.get_bytes()

    # write content of active cache volume to passive cache exported obj
    write_vol(vol2, queue, data)

    assert cache_md5 == cache2_exp_obj_vol.md5()

    # volumes should have the same data
    assert sec_cache_backend_vol.get_bytes() == prim_cache_backend_vol.get_bytes()

    # failover
    cache2.standby_detach()
    cache2.standby_activate(sec_cache_backend_vol, open_cores=False)
    core = Core(core_backend_vol)
    cache2.add_core(core, try_add=True)
    vol = CoreVolume(core, open=True)

    # check data consistency
    assert data_md5 == vol.md5()


def test_standby_load_writes_count(pyocf_ctx):
    # Prepare a volume with valid metadata
    device = RamVolume(Size.from_MiB(40))
    cache = Cache.start_on_device(device, cache_mode=CacheMode.WB)
    cache.stop()

    device.reset_stats()

    cache = Cache(owner=pyocf_ctx)
    cache.start_cache()

    cache.standby_load(device, perform_test=False)

    assert device.get_stats()[IoDir.WRITE] == 0


def test_failover_line_size_mismatch(pyocf_2_ctx):
    ctx = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB
    cls2 = CacheLineSize.LINE_64KiB
    vol1 = RamVolume(Size.from_MiB(150), uuid="cv1")
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.attach_device(vol1, force=False)

    core_vol = RamVolume(Size.from_MiB(150))
    core = Core(core_vol)
    cache.add_core(core)

    data = vol1.get_bytes()

    cache.stop()
    vol1 = None

    vol2 = RamVolume(Size.from_MiB(150), uuid="cv2")
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls2)
    cache.start_cache()
    cache.standby_attach(vol2)
    cache_vol = CacheVolume(cache, open=True)

    write_vol(cache_vol, cache.get_default_queue(), data)

    cache.get_conf()["cache_line_size"] == cls2

    cache.standby_detach()

    # first attempt to activate with size mismatch
    with pytest.raises(OcfError) as ex:
        cache.standby_activate(vol2)
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_START_CACHE_FAIL

    # second attempt to activate with size mismatch
    with pytest.raises(OcfError) as ex:
        cache.standby_activate(vol2)
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_START_CACHE_FAIL

    cache.stop()
    cache = Cache(owner=ctx, cache_mode=mode, cache_line_size=cls)
    cache.start_cache()
    cache.standby_load(vol2)
    cache.standby_detach()
    cache.standby_activate(vol2)

    cache.get_conf()["cache_line_size"] == cls

    cache.stop()


def test_failover_passive_first(pyocf_2_ctx):
    ctx1 = pyocf_2_ctx[0]
    ctx2 = pyocf_2_ctx[1]
    mode = CacheMode.WB
    cls = CacheLineSize.LINE_4KiB

    prim_cache_backend_vol = RamVolume(Size.from_MiB(150))
    core_backend_vol = RamVolume(Size.from_MiB(1))
    sec_cache_backend_vol = RamVolume(Size.from_MiB(150))

    # passive cache with directly on ram disk
    cache2 = Cache(owner=ctx2, cache_mode=mode, cache_line_size=cls)
    cache2.start_cache()
    cache2.standby_attach(sec_cache_backend_vol)

    # volume replicating cache1 ramdisk writes to cache2 cache exported object
    cache2_exp_obj_vol = CacheVolume(cache2, open=True)
    cache1_cache_vol = ReplicatedVolume(prim_cache_backend_vol, cache2_exp_obj_vol)

    # active cache
    cache1 = Cache.start_on_device(cache1_cache_vol, ctx1, cache_mode=mode, cache_line_size=cls)
    core = Core(core_backend_vol)
    cache1.add_core(core)
    core_vol = CoreVolume(core, open=True)
    queue = cache1.get_default_queue()

    # some I/O
    r = (
        Rio()
        .target(core_vol)
        .njobs(1)
        .readwrite(ReadWrite.WRITE)
        .size(Size.from_MiB(1))
        .qd(1)
        .run([queue])
    )

    # capture checksum before simulated active host failure
    md5 = core_vol.md5()

    # offline primary cache volume and stop primary cache to simulate active host
    # failure
    cache1_cache_vol.offline()
    with pytest.raises(OcfError) as ex:
        cache1.stop()
    assert ex.value.error_code == OcfErrorCode.OCF_ERR_WRITE_CACHE

    # failover
    cache2.standby_detach()
    cache2.standby_activate(sec_cache_backend_vol, open_cores=False)

    # add core explicitly with "try_add" to workaround pyocf limitations
    core = Core(core_backend_vol)
    cache2.add_core(core, try_add=True)
    core_vol = CoreVolume(core, open=True)

    assert md5 == core_vol.md5()
