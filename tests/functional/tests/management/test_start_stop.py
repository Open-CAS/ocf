#
# Copyright(c) 2019-2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import logging
from ctypes import (
    c_int,
    c_void_p,
    byref,
    c_uint32,
    cast,
    create_string_buffer,
    c_char_p,
)
from random import randrange
from itertools import count

import pytest

from pyocf.ocf import OcfLib
from pyocf.types.cache import (
    Cache,
    CacheMode,
    MetadataLayout,
    CleaningPolicy,
    CacheConfig,
    PromotionPolicy,
    Backfill,
    CacheDeviceConfig,
    CacheAttachConfig,
)
from pyocf.types.core import Core
from pyocf.types.ctx import OcfCtx
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.queue import Queue
from pyocf.types.shared import (
    Uuid,
    OcfError,
    OcfErrorCode,
    OcfCompletion,
    CacheLineSize,
    SeqCutOffPolicy,
)
from pyocf.types.volume import Volume, RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size

logger = logging.getLogger(__name__)


def test_start_check_default(pyocf_ctx):
    """Test if default values are correct after start.
    """

    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(10))
    cache = Cache.start_on_device(cache_device)

    core = Core.using_device(core_device)
    cache.add_core(core)

    # Check if values are default
    stats = cache.get_stats()
    assert stats["conf"]["cleaning_policy"] == CleaningPolicy.DEFAULT
    assert stats["conf"]["cache_mode"] == CacheMode.DEFAULT
    assert stats["conf"]["cache_line_size"] == CacheLineSize.DEFAULT

    core_stats = core.get_stats()
    assert core_stats["seq_cutoff_policy"] == SeqCutOffPolicy.DEFAULT


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("mode", CacheMode)
def test_start_write_first_and_check_mode(pyocf_ctx, mode: CacheMode, cls: CacheLineSize):
    """Test starting cache in different modes with different cache line sizes.
    After start check proper cache mode behaviour, starting with write operation.
    """

    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(10))
    cache = Cache.start_on_device(cache_device, cache_mode=mode, cache_line_size=cls)
    core = Core.using_device(core_device)

    cache.add_core(core)
    vol = CoreVolume(core, open=True)
    queue = cache.get_default_queue()

    logger.info("[STAGE] Initial write to exported object")
    cache_device.reset_stats()
    core_device.reset_stats()

    test_data = Data.from_string("This is test data")
    io_to_core(vol, queue, test_data, Size.from_sector(1).B)
    check_stats_write_empty(core, mode, cls)

    logger.info("[STAGE] Read from exported object after initial write")
    io_from_exported_object(vol, queue, test_data.size, Size.from_sector(1).B)
    check_stats_read_after_write(core, mode, cls, True)

    logger.info("[STAGE] Write to exported object after read")
    cache_device.reset_stats()
    core_device.reset_stats()

    test_data = Data.from_string("Changed test data")

    io_to_core(vol, queue, test_data, Size.from_sector(1).B)
    check_stats_write_after_read(core, mode, cls)

    check_md5_sums(core, mode)


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("mode", CacheMode)
def test_start_read_first_and_check_mode(pyocf_ctx, mode: CacheMode, cls: CacheLineSize):
    """Starting cache in different modes with different cache line sizes.
    After start check proper cache mode behaviour, starting with read operation.
    """

    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(5))
    cache = Cache.start_on_device(cache_device, cache_mode=mode, cache_line_size=cls)
    core = Core.using_device(core_device)

    cache.add_core(core)
    front_vol = CoreVolume(core, open=True)
    bottom_vol = core.get_volume()
    queue = cache.get_default_queue()

    logger.info("[STAGE] Initial write to core device")
    test_data = Data.from_string("This is test data")
    io_to_core(bottom_vol, queue, test_data, Size.from_sector(1).B)

    cache_device.reset_stats()
    core_device.reset_stats()

    logger.info("[STAGE] Initial read from exported object")
    io_from_exported_object(front_vol, queue, test_data.size, Size.from_sector(1).B)
    check_stats_read_empty(core, mode, cls)

    logger.info("[STAGE] Write to exported object after initial read")
    cache_device.reset_stats()
    core_device.reset_stats()

    test_data = Data.from_string("Changed test data")

    io_to_core(front_vol, queue, test_data, Size.from_sector(1).B)

    check_stats_write_after_read(core, mode, cls, True)

    logger.info("[STAGE] Read from exported object after write")
    io_from_exported_object(front_vol, queue, test_data.size, Size.from_sector(1).B)
    check_stats_read_after_write(core, mode, cls)

    check_md5_sums(core, mode)


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("mode", CacheMode)
@pytest.mark.parametrize("layout", MetadataLayout)
def test_start_params(pyocf_ctx, mode: CacheMode, cls: CacheLineSize, layout: MetadataLayout):
    """Starting cache with different parameters.
    Check if cache starts without errors.
    If possible check whether cache reports properly set parameters.
    """
    cache_device = RamVolume(Size.from_MiB(50))
    queue_size = randrange(60000, 2 ** 32)
    unblock_size = randrange(1, queue_size)
    volatile_metadata = randrange(2) == 1
    unaligned_io = randrange(2) == 1
    submit_fast = randrange(2) == 1
    name = "test"

    logger.info("[STAGE] Start cache")
    cache = Cache.start_on_device(
        cache_device,
        cache_mode=mode,
        cache_line_size=cls,
        name=name,
        metadata_volatile=volatile_metadata,
        max_queue_size=queue_size,
        queue_unblock_size=unblock_size,
        pt_unaligned_io=unaligned_io,
        use_submit_fast=submit_fast,
    )

    stats = cache.get_stats()
    assert stats["conf"]["cache_mode"] == mode, "Cache mode"
    assert stats["conf"]["cache_line_size"] == cls, "Cache line size"
    assert cache.get_name() == name, "Cache name"
    # TODO: metadata_volatile, max_queue_size,
    #  queue_unblock_size, pt_unaligned_io, use_submit_fast
    # TODO: test in functional tests


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("mode", CacheMode)
@pytest.mark.parametrize("with_flush", {True, False})
def test_stop(pyocf_ctx, mode: CacheMode, cls: CacheLineSize, with_flush: bool):
    """Stopping cache.
    Check if cache is stopped properly in different modes with or without preceding flush operation.
    """

    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(5))
    cache = Cache.start_on_device(cache_device, cache_mode=mode, cache_line_size=cls)
    core = Core.using_device(core_device)

    cache.add_core(core)
    front_vol = CoreVolume(core, open=True)
    queue = cache.get_default_queue()

    cls_no = 10

    run_io_and_cache_data_if_possible(core, mode, cls, cls_no)

    stats = cache.get_stats()
    assert int(stats["conf"]["dirty"]) == (
        cls_no if mode.lazy_write() else 0
    ), "Dirty data before MD5"

    md5_exported_core = front_vol.md5()

    if with_flush:
        cache.flush()
    cache.stop()

    if mode.lazy_write() and not with_flush:
        assert (
            core_device.md5() != md5_exported_core
        ), "MD5 check: core device vs exported object with dirty data"
    else:
        assert (
            core_device.md5() == md5_exported_core
        ), "MD5 check: core device vs exported object with clean data"


def test_start_stop_multiple(pyocf_ctx):
    """Starting/stopping multiple caches.
    Check whether OCF allows for starting multiple caches and stopping them in random order
    """

    caches = []
    caches_no = randrange(6, 11)
    for i in range(1, caches_no):
        cache_device = RamVolume(Size.from_MiB(50))
        cache_name = f"cache{i}"
        cache_mode = CacheMode(randrange(0, len(CacheMode)))
        size = 4096 * 2 ** randrange(0, len(CacheLineSize))
        cache_line_size = CacheLineSize(size)

        cache = Cache.start_on_device(
            cache_device, name=cache_name, cache_mode=cache_mode, cache_line_size=cache_line_size,
        )
        caches.append(cache)
        stats = cache.get_stats()
        assert stats["conf"]["cache_mode"] == cache_mode, "Cache mode"
        assert stats["conf"]["cache_line_size"] == cache_line_size, "Cache line size"
        assert stats["conf"]["cache_name"] == cache_name, "Cache name"

    caches.sort(key=lambda e: randrange(1000))
    for cache in caches:
        logger.info("Getting stats before stopping cache")
        stats = cache.get_stats()
        cache_name = stats["conf"]["cache_name"]
        cache.stop()
        assert Cache.get_by_name(cache_name, pyocf_ctx) != 0, "Try getting cache after stopping it"


def test_100_start_stop(pyocf_ctx):
    """Starting/stopping stress test.
    Check OCF behaviour when cache is started and stopped continuously
    """

    for i in range(1, 101):
        cache_device = RamVolume(Size.from_MiB(50))
        cache_name = f"cache{i}"
        cache_mode = CacheMode(randrange(0, len(CacheMode)))
        size = 4096 * 2 ** randrange(0, len(CacheLineSize))
        cache_line_size = CacheLineSize(size)

        cache = Cache.start_on_device(
            cache_device, name=cache_name, cache_mode=cache_mode, cache_line_size=cache_line_size,
        )
        stats = cache.get_stats()
        assert stats["conf"]["cache_mode"] == cache_mode, "Cache mode"
        assert stats["conf"]["cache_line_size"] == cache_line_size, "Cache line size"
        assert stats["conf"]["cache_name"] == cache_name, "Cache name"
        cache.stop()
        assert Cache.get_by_name("cache1", pyocf_ctx) != 0, "Try getting cache after stopping it"


def test_start_stop_incrementally(pyocf_ctx):
    """Starting/stopping multiple caches incrementally.
    Check whether OCF behaves correctly when few caches at a time are
    in turns added and removed (#added > #removed) until their number reaches limit,
    and then proportions are reversed and number of caches gradually falls to 0.
    """

    counter = count()
    caches = []
    caches_limit = 10
    add = True
    run = True
    increase = True
    while run:
        if add:
            for i in range(0, randrange(3, 5) if increase else randrange(1, 3)):
                cache_device = RamVolume(Size.from_MiB(50))
                cache_name = f"cache{next(counter)}"
                cache_mode = CacheMode(randrange(0, len(CacheMode)))
                size = 4096 * 2 ** randrange(0, len(CacheLineSize))
                cache_line_size = CacheLineSize(size)

                cache = Cache.start_on_device(
                    cache_device,
                    name=cache_name,
                    cache_mode=cache_mode,
                    cache_line_size=cache_line_size,
                )
                caches.append(cache)
                stats = cache.get_stats()
                assert stats["conf"]["cache_mode"] == cache_mode, "Cache mode"
                assert stats["conf"]["cache_line_size"] == cache_line_size, "Cache line size"
                assert stats["conf"]["cache_name"] == cache_name, "Cache name"
                if len(caches) == caches_limit:
                    increase = False
        else:
            for i in range(0, randrange(1, 3) if increase else randrange(3, 5)):
                if len(caches) == 0:
                    run = False
                    break
                cache = caches.pop()
                logger.info("Getting stats before stopping cache")
                stats = cache.get_stats()
                cache_name = stats["conf"]["cache_name"]
                cache.stop()
                assert (
                    Cache.get_by_name(cache_name, pyocf_ctx) != 0
                ), "Try getting cache after stopping it"
        add = not add


@pytest.mark.parametrize("mode", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
def test_start_cache_same_id(pyocf_ctx, mode, cls):
    """Adding two caches with the same name
    Check that OCF does not allow for 2 caches to be started with the same cache_name
    """

    cache_device1 = RamVolume(Size.from_MiB(50))
    cache_device2 = RamVolume(Size.from_MiB(50))
    cache_name = "cache"
    cache = Cache.start_on_device(
        cache_device1, cache_mode=mode, cache_line_size=cls, name=cache_name
    )
    cache.get_stats()

    with pytest.raises(OcfError, match="OCF_ERR_CACHE_EXIST"):
        cache = Cache.start_on_device(
            cache_device2, cache_mode=mode, cache_line_size=cls, name=cache_name
        )
    cache.get_stats()


@pytest.mark.parametrize("cls", CacheLineSize)
def test_start_cache_huge_device(pyocf_ctx_log_buffer, cls):
    """
    Test whether we can start cache which would overflow ocf_cache_line_t type.
    pass_criteria:
      - Starting cache on device too big to handle should fail
    """

    class HugeDevice(Volume):
        def get_length(self):
            return Size.from_B((cls * c_uint32(-1).value))

        def submit_io(self, io):
            io.contents._end(io, 0)

    OcfCtx.get_default().register_volume_type(HugeDevice)

    cache_device = HugeDevice()

    with pytest.raises(OcfError, match="OCF_ERR_INVAL_CACHE_DEV"):
        cache = Cache.start_on_device(cache_device, cache_line_size=cls, metadata_volatile=True)

    assert any(
        [line.find("exceeds maximum") > 0 for line in pyocf_ctx_log_buffer.get_lines()]
    ), "Expected to find log notifying that max size was exceeded"


@pytest.mark.parametrize("mode", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
def test_start_cache_same_device(pyocf_ctx, mode, cls):
    """Adding two caches using the same cache device
    Check that OCF does not allow for 2 caches using the same cache device to be started.
    Low level OCF API is used for attach instead of Cache::attach_device as the latter operates
    on pyocf Volume objects and this test requires explicit construction of two volumes with
    identical UUID. Pyocf does not allow for two Volume objects with the same UUID, as these
    represent a resource that should be uniquely identified by UUID. So we need to create
    two distinct OCF volumes with identical UUID and pass them to OCF cache attach method.
    """
    _uuid = "cache_dev"

    cache_device = RamVolume(Size.from_MiB(50), uuid=_uuid)

    uuid = Uuid(
        _data=cast(create_string_buffer(_uuid.encode("ascii")), c_char_p), _size=len(_uuid) + 1,
    )

    lib = OcfLib.getInstance()

    vol1 = c_void_p()
    vol2 = c_void_p()

    result = lib.ocf_volume_create(byref(vol1), pyocf_ctx.ocf_volume_type[RamVolume], byref(uuid))
    assert result == 0
    result = lib.ocf_volume_create(byref(vol2), pyocf_ctx.ocf_volume_type[RamVolume], byref(uuid))
    assert result == 0

    dev_cfg = CacheDeviceConfig(_volume=vol1, _perform_test=False, _volume_params=None)

    attach_cfg = CacheAttachConfig(
        _device=dev_cfg,
        _cache_line_size=cls,
        _open_cores=True,
        _force=False,
        _discard_on_start=False,
    )

    # start first cache instance
    cache1 = Cache(pyocf_ctx, cache_mode=mode, cache_line_size=cls, name="cache1")
    cache1.start_cache()
    cache1.write_lock()
    c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
    lib.ocf_mngt_cache_attach(cache1.cache_handle, byref(attach_cfg), c, None)
    c.wait()
    cache1.write_unlock()
    assert not c.results["error"]

    # attempt to start second cache instance on a volume with the same UUID
    attach_cfg._device._volume = vol2
    cache2 = Cache(pyocf_ctx, cache_mode=mode, cache_line_size=cls, name="cache2")
    cache2.start_cache()
    cache2.write_lock()
    c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
    lib.ocf_mngt_cache_attach(cache2.cache_handle, byref(attach_cfg), c, None)
    c.wait()
    cache2.write_unlock()

    assert c.results["error"]
    error_code = OcfErrorCode(abs(c.results["error"]))
    assert error_code == OcfErrorCode.OCF_ERR_NOT_OPEN_EXC

    cache1.stop()
    cache2.stop()

    lib = OcfLib.getInstance().ocf_volume_destroy(vol1)
    lib = OcfLib.getInstance().ocf_volume_destroy(vol2)

    del cache_device


@pytest.mark.parametrize("mode", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
def test_start_too_small_device(pyocf_ctx, mode, cls):
    """Starting cache with device below 100MiB
    Check if starting cache with device below minimum size is blocked
    """

    cache_device = RamVolume(Size.from_B(20 * 1024 * 1024 - 1))

    with pytest.raises(OcfError, match="OCF_ERR_INVAL_CACHE_DEV"):
        Cache.start_on_device(cache_device, cache_mode=mode, cache_line_size=cls)


def test_start_stop_noqueue(pyocf_ctx):
    cfg = CacheConfig()
    pyocf_ctx.lib.ocf_mngt_cache_config_set_default_wrapper(byref(cfg))
    cfg._metadata_volatile = True
    cfg._name = "Test".encode("ascii")

    cache_handle = c_void_p()
    status = pyocf_ctx.lib.ocf_mngt_cache_start(
        pyocf_ctx.ctx_handle, byref(cache_handle), byref(cfg), None
    )
    assert not status, "Failed to start cache: {}".format(status)

    # stop without creating mngmt queue
    c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
    pyocf_ctx.lib.ocf_mngt_cache_stop(cache_handle, c, None)
    c.wait()
    assert not c.results["error"], "Failed to stop cache: {}".format(c.results["error"])


def run_io_and_cache_data_if_possible(core, mode, cls, cls_no):
    front_vol = core.get_front_volume()
    bottom_vol = core.get_volume()
    queue = core.cache.get_default_queue()

    test_data = Data(cls_no * cls)

    if mode in {CacheMode.WI, CacheMode.WA}:
        logger.info("[STAGE] Write to core device")
        io_to_core(bottom_vol, queue, test_data, 0)
        logger.info("[STAGE] Read from exported object")
        io_from_exported_object(front_vol, queue, test_data.size, 0)
    else:
        logger.info("[STAGE] Write to exported object")
        io_to_core(front_vol, queue, test_data, 0)

    stats = core.cache.get_stats()
    assert stats["usage"]["occupancy"]["value"] == (
        (cls_no * cls / CacheLineSize.LINE_4KiB) if mode != CacheMode.PT else 0
    ), "Occupancy"


def io_to_core(vol: Volume, queue: Queue, data: Data, offset: int):
    io = vol.new_io(queue, offset, data.size, IoDir.WRITE, 0, 0)
    io.set_data(data)

    completion = OcfCompletion([("err", c_int)])
    io.callback = completion.callback
    io.submit()
    completion.wait()

    assert completion.results["err"] == 0, "IO to exported object completion"


def io_from_exported_object(vol: Volume, queue: Queue, buffer_size: int, offset: int):
    read_buffer = Data(buffer_size)
    io = vol.new_io(queue, offset, read_buffer.size, IoDir.READ, 0, 0)
    io.set_data(read_buffer)

    completion = OcfCompletion([("err", c_int)])
    io.callback = completion.callback
    io.submit()
    completion.wait()

    assert completion.results["err"] == 0, "IO from exported object completion"
    return read_buffer


def check_stats_read_empty(core: Core, mode: CacheMode, cls: CacheLineSize):
    core.cache.settle()
    stats = core.cache.get_stats()
    assert stats["conf"]["cache_mode"] == mode, "Cache mode"
    assert core.cache.device.get_stats()[IoDir.WRITE] == (
        1 if mode.read_insert() else 0
    ), "Writes to cache device"
    assert core.device.get_stats()[IoDir.READ] == 1, "Reads from core device"
    assert stats["req"]["rd_full_misses"]["value"] == (
        0 if mode == CacheMode.PT else 1
    ), "Read full misses"
    assert stats["usage"]["occupancy"]["value"] == (
        (cls / CacheLineSize.LINE_4KiB) if mode.read_insert() else 0
    ), "Occupancy"


def check_stats_write_empty(core: Core, mode: CacheMode, cls: CacheLineSize):
    core.cache.settle()
    stats = core.cache.get_stats()
    assert stats["conf"]["cache_mode"] == mode, "Cache mode"
    # TODO(ajrutkow): why 1 for WT ??
    assert core.cache.device.get_stats()[IoDir.WRITE] == (
        2 if mode.lazy_write() else (1 if mode == CacheMode.WT else 0)
    ), "Writes to cache device"
    assert core.device.get_stats()[IoDir.WRITE] == (
        0 if mode.lazy_write() else 1
    ), "Writes to core device"
    assert stats["req"]["wr_full_misses"]["value"] == (
        1 if mode.write_insert() else 0
    ), "Write full misses"
    assert stats["usage"]["occupancy"]["value"] == (
        (cls / CacheLineSize.LINE_4KiB) if mode.write_insert() else 0
    ), "Occupancy"


def check_stats_write_after_read(
    core: Core, mode: CacheMode, cls: CacheLineSize, read_from_empty=False
):
    core.cache.settle()
    stats = core.cache.get_stats()
    assert core.cache.device.get_stats()[IoDir.WRITE] == (
        0
        if mode in {CacheMode.WI, CacheMode.PT}
        else (2 if read_from_empty and mode.lazy_write() else 1)
    ), "Writes to cache device"
    assert core.device.get_stats()[IoDir.WRITE] == (
        0 if mode.lazy_write() else 1
    ), "Writes to core device"
    assert stats["req"]["wr_hits"]["value"] == (
        1
        if (mode.read_insert() and mode != CacheMode.WI)
        or (mode.write_insert() and not read_from_empty)
        else 0
    ), "Write hits"
    assert stats["usage"]["occupancy"]["value"] == (
        0 if mode in {CacheMode.WI, CacheMode.PT} else (cls / CacheLineSize.LINE_4KiB)
    ), "Occupancy"


def check_stats_read_after_write(core, mode, cls, write_to_empty=False):
    core.cache.settle()
    stats = core.cache.get_stats()
    assert core.cache.device.get_stats()[IoDir.WRITE] == (
        2 if mode.lazy_write() else (0 if mode == CacheMode.PT else 1)
    ), "Writes to cache device"
    assert core.cache.device.get_stats()[IoDir.READ] == (
        1
        if mode in {CacheMode.WT, CacheMode.WB, CacheMode.WO}
        or (mode == CacheMode.WA and not write_to_empty)
        else 0
    ), "Reads from cache device"
    assert core.device.get_stats()[IoDir.READ] == (
        0
        if mode in {CacheMode.WB, CacheMode.WO, CacheMode.WT}
        or (mode == CacheMode.WA and not write_to_empty)
        else 1
    ), "Reads from core device"
    assert stats["req"]["rd_full_misses"]["value"] == (
        1 if mode in {CacheMode.WA, CacheMode.WI} else 0
    ) + (0 if write_to_empty or mode in {CacheMode.PT, CacheMode.WA} else 1), "Read full misses"
    assert stats["req"]["rd_hits"]["value"] == (
        1
        if mode in {CacheMode.WT, CacheMode.WB, CacheMode.WO}
        or (mode == CacheMode.WA and not write_to_empty)
        else 0
    ), "Read hits"
    assert stats["usage"]["occupancy"]["value"] == (
        0 if mode == CacheMode.PT else (cls / CacheLineSize.LINE_4KiB)
    ), "Occupancy"


def check_md5_sums(core: Core, mode: CacheMode):
    if mode.lazy_write():
        assert (
            core.device.md5() != core.get_front_volume().md5()
        ), "MD5 check: core device vs exported object without flush"
        core.cache.flush()
        assert (
            core.device.md5() == core.get_front_volume().md5()
        ), "MD5 check: core device vs exported object after flush"
    else:
        assert (
            core.device.md5() == core.get_front_volume().md5()
        ), "MD5 check: core device vs exported object"

