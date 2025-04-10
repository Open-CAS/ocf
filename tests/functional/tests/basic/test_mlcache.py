#
# Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import c_int
from threading import Thread
import time

import pytest

from pyocf.utils import Size as S
from pyocf.types.cache import Cache
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.shared import OcfCompletion, OcfError
from pyocf.types.volume import RamVolume, ErrorDevice
from pyocf.types.volume_core import CoreVolume
from pyocf.rio import Rio, ReadWrite
from pyocf.ocf_utils import core_sync_read, core_sync_write


def test_create_destroy(pyocf_ctx):
    lower = Cache.start_on_device(
        RamVolume(S.from_MiB(50)),
        name="lower",
        metadata_volatile=True
    )
    middle = Cache.start_on_device(
        RamVolume(S.from_MiB(50)),
        name="middle",
        metadata_volatile=True
    )
    upper = Cache.start_on_device(
        RamVolume(S.from_MiB(50)),
        name="upper",
        metadata_volatile=True
    )

    lower.ml_add_cache(middle)
    lower.ml_add_cache(upper)

    lower.stop()

    assert Cache.get_by_name("upper") != 0, "Upper cache exists after stop!"
    assert Cache.get_by_name("middle") != 0, "Middle cache exists after stop!"
    assert Cache.get_by_name("lower") != 0, "Lower cache exists after stop!"


def test_stop_upper_negative(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache3 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    cache1.ml_add_cache(cache2)
    cache1.ml_add_cache(cache3)

    with pytest.raises(OcfError, match="OCF_ERR_CACHE_NOT_MAIN"):
        cache2.stop()

    with pytest.raises(OcfError, match="OCF_ERR_CACHE_NOT_MAIN"):
        cache3.stop()


def test_remove_upper_layer(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache3 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    cache1.ml_add_cache(cache2)
    cache1.ml_add_cache(cache3)

    cache1.ml_remove_cache()
    cache1.ml_remove_cache()


def test_remove_upper_layer_twice_negative(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    cache1.ml_add_cache(cache2)

    cache1.ml_remove_cache()

    with pytest.raises(OcfError):
        cache1.ml_remove_cache()


def test_remove_upper_layer_cache_negative(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    with pytest.raises(OcfError):
        cache1.ml_remove_cache()


def test_create_wrong_layering_1(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache3 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    cache1.ml_add_cache(cache2)
    with pytest.raises(OcfError, match="OCF_ERR_CACHE_NOT_MAIN"):
        cache2.ml_add_cache(cache3)


def test_create_wrong_layering_2(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache3 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    cache1.ml_add_cache(cache2)
    with pytest.raises(OcfError, match="OCF_ERR_CACHE_IS_MULTI_LEVEL"):
        cache3.ml_add_cache(cache2)


def test_add_core_to_ml(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache3 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    core1 = Core.using_device(RamVolume(S.from_MiB(100)))
    core2 = Core.using_device(RamVolume(S.from_MiB(100)))

    cache1.ml_add_cache(cache2)
    cache1.ml_add_cache(cache3)

    cache1.add_core(core1)
    cache1.add_core(core2)

    assert cache1.get_conf()["core_count"] == 2
    assert cache2.get_conf()["core_count"] == 2
    assert cache3.get_conf()["core_count"] == 2

    cache1.stop()


def test_add_cores_remove_upper_cache_ml(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache3 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    core1 = Core.using_device(RamVolume(S.from_MiB(100)))
    core2 = Core.using_device(RamVolume(S.from_MiB(100)))

    cache1.ml_add_cache(cache2)
    cache1.ml_add_cache(cache3)

    cache1.add_core(core1)
    cache1.add_core(core2)

    assert cache1.get_conf()["core_count"] == 2
    assert cache2.get_conf()["core_count"] == 2
    assert cache3.get_conf()["core_count"] == 2

    cache1.ml_remove_cache()

    assert cache1.get_conf()["core_count"] == 2
    assert cache2.get_conf()["core_count"] == 2
    assert cache3.get_conf()["core_count"] == 0

    cache1.ml_remove_cache()

    assert cache1.get_conf()["core_count"] == 2
    assert cache2.get_conf()["core_count"] == 0
    assert cache3.get_conf()["core_count"] == 0



def test_add_core_before_ml(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache3 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    core = Core.using_device(RamVolume(S.from_MiB(100)))
    cache1.add_core(core)

    cache1.ml_add_cache(cache2)
    cache1.ml_add_cache(cache3)

    assert cache1.get_conf()["core_count"] == 1
    assert cache2.get_conf()["core_count"] == 1
    assert cache3.get_conf()["core_count"] == 1


def test_add_core_before_ml_error(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    core_volume = ErrorDevice(RamVolume(S.from_MiB(100)), armed=False)
    core = Core.using_device(core_volume)
    cache1.add_core(core)

    core_volume.arm_length()
    with pytest.raises(OcfError):
        cache1.ml_add_cache(cache2)


def test_rollback_add_upper_cache(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    core1 = Core.using_device(RamVolume(S.from_MiB(100)))
    core_volume = ErrorDevice(RamVolume(S.from_MiB(100)), armed=False)
    core2 = Core.using_device(core_volume)
    cache1.add_core(core1)
    cache1.add_core(core2)

    core_volume.arm_length()
    with pytest.raises(OcfError):
        cache1.ml_add_cache(cache2)

    # if rollback was done correctly, there should be no cores in upper cache
    assert cache2.get_conf()["core_count"] == 0


def test_remove_core_added_before_ml(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache3 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    core = Core.using_device(RamVolume(S.from_MiB(100)))
    cache1.add_core(core)

    cache1.ml_add_cache(cache2)
    cache1.ml_add_cache(cache3)

    cache1.remove_core(core)

    assert cache1.get_conf()["core_count"] == 0
    assert cache2.get_conf()["core_count"] == 0
    assert cache3.get_conf()["core_count"] == 0


def test_remove_core_added_to_ml(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache3 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)

    core = Core.using_device(RamVolume(S.from_MiB(100)))

    cache1.ml_add_cache(cache3)
    cache1.ml_add_cache(cache2)

    cache1.add_core(core)

    cache1.remove_core(core)

    assert cache1.get_conf()["core_count"] == 0
    assert cache2.get_conf()["core_count"] == 0
    assert cache3.get_conf()["core_count"] == 0


def test_remove_core_after_io(pyocf_ctx):
    lower = Cache.start_on_device(
        RamVolume(S.from_MiB(50)),
        metadata_volatile=True
    )
    upper = Cache.start_on_device(
        RamVolume(S.from_MiB(50)),
        metadata_volatile=True
    )

    lower.ml_add_cache(upper)

    core = Core.using_device(RamVolume(S.from_MiB(100)))
    lower.add_core(core)

    cfv = CoreVolume(core)
    queue = core.cache.get_default_queue()
    Rio().target(cfv).bs(S.from_KiB(4)).readwrite(ReadWrite.WRITE).size(S.from_KiB(4)).run([queue])

    lower.remove_core(core)

    assert lower.get_conf()["core_count"] == 0
    assert upper.get_conf()["core_count"] == 0


def test_io_2_levels(pyocf_ctx):
    def assert_ios(expected_stats):
        upper_cache.settle()
        lower_cache.settle()
        udev_stats = udev.get_stats()
        ldev_stats = ldev.get_stats()
        cdev_stats = cdev.get_stats()
        stats = {
            'ur' : udev_stats[IoDir.READ],
            'uw' : udev_stats[IoDir.WRITE],
            'lr' : ldev_stats[IoDir.READ],
            'lw' : ldev_stats[IoDir.WRITE],
            'cr' : cdev_stats[IoDir.READ],
            'cw' : cdev_stats[IoDir.WRITE],
        }
        assert stats == expected_stats

    def reset_stats():
        udev.reset_stats()
        ldev.reset_stats()
        cdev.reset_stats()

    udev = RamVolume(S.from_MiB(50), uuid="udev")
    ldev = RamVolume(S.from_MiB(100), uuid="ldev")
    cdev = RamVolume(S.from_MiB(200), uuid="cdev")
    lower_cache = Cache.start_on_device(ldev, name="lower", metadata_volatile=True)
    upper_cache = Cache.start_on_device(udev, name="upper", metadata_volatile=True)
    lower_cache.ml_add_cache(upper_cache)

    core = Core.using_device(cdev)
    lower_cache.add_core(core)

    cfv = CoreVolume(core)
    queue = core.cache.get_default_queue()
    r = Rio().target(cfv).bs(S.from_KiB(4))

    # Single cache line write insert
    reset_stats()
    r.copy().readwrite(ReadWrite.WRITE).size(S.from_KiB(4)).run([queue])
    assert_ios({'ur' : 0, 'uw' : 1, 'lr' : 0, 'lw' : 1, 'cr' : 0, 'cw' : 1})

    # Single cache line read insert
    reset_stats()
    r.copy().readwrite(ReadWrite.READ).offset(S.from_KiB(4)).size(S.from_KiB(4)).run([queue])
    assert_ios({'ur' : 0, 'uw' : 1, 'lr' : 0, 'lw' : 1, 'cr' : 1, 'cw' : 0})

    # Single cache line read hit (L0)
    reset_stats()
    r.copy().readwrite(ReadWrite.READ).size(S.from_KiB(4)).run([queue])
    assert_ios({'ur' : 1, 'uw' : 0, 'lr' : 0, 'lw' : 0, 'cr' : 0, 'cw' : 0})

    # Single cache line write hit (L0)
    reset_stats()
    r.copy().readwrite(ReadWrite.WRITE).size(S.from_KiB(4)).run([queue])
    assert_ios({'ur' : 0, 'uw' : 1, 'lr' : 0, 'lw' : 1, 'cr' : 0, 'cw' : 1})

    # Trigger eviction from L0 by writing more than cache size
    r.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(60)).run([queue])

    # Single cache line read hit (L1)
    reset_stats()
    r.copy().readwrite(ReadWrite.READ).size(S.from_KiB(4)).run([queue])
    assert_ios({'ur' : 0, 'uw' : 1, 'lr' : 1, 'lw' : 0, 'cr' : 0, 'cw' : 0})


def test_io_3_levels(pyocf_ctx):
    def assert_ios(expected_stats):
        l0cache.settle()
        l1cache.settle()
        l2cache.settle()
        l0dev_stats = l0dev.get_stats()
        l1dev_stats = l1dev.get_stats()
        l2dev_stats = l2dev.get_stats()
        cdev_stats = cdev.get_stats()
        stats = {
            'l0r' : l0dev_stats[IoDir.READ],
            'l0w' : l0dev_stats[IoDir.WRITE],
            'l1r' : l1dev_stats[IoDir.READ],
            'l1w' : l1dev_stats[IoDir.WRITE],
            'l2r' : l2dev_stats[IoDir.READ],
            'l2w' : l2dev_stats[IoDir.WRITE],
            'cr' : cdev_stats[IoDir.READ],
            'cw' : cdev_stats[IoDir.WRITE],
        }
        assert stats == expected_stats

    def reset_stats():
        l0dev.reset_stats()
        l1dev.reset_stats()
        l2dev.reset_stats()
        cdev.reset_stats()

    l0dev = RamVolume(S.from_MiB(50), uuid="l0dev")
    l1dev = RamVolume(S.from_MiB(100), uuid="l1dev")
    l2dev = RamVolume(S.from_MiB(150), uuid="l2dev")
    cdev = RamVolume(S.from_MiB(200), uuid="cdev")
    l0cache = Cache.start_on_device(l0dev, name="l0cache", metadata_volatile=True)
    l1cache = Cache.start_on_device(l1dev, name="l1cache", metadata_volatile=True)
    l2cache = Cache.start_on_device(l2dev, name="l2cache", metadata_volatile=True)

    l2cache.ml_add_cache(l1cache)
    l2cache.ml_add_cache(l0cache)

    core = Core.using_device(cdev)
    l2cache.add_core(core)

    cfv = CoreVolume(core)
    queue = core.cache.get_default_queue()
    r = Rio().target(cfv).bs(S.from_KiB(4))

    # Single cache line write insert
    reset_stats()
    r.copy().readwrite(ReadWrite.WRITE).size(S.from_KiB(4)).run([queue])
    assert_ios({
        'l0r' : 0, 'l0w' : 1,
        'l1r' : 0, 'l1w' : 1,
        'l2r' : 0, 'l2w' : 1,
        'cr'  : 0, 'cw'  : 1
    })

    # Single cache line read insert
    reset_stats()
    r.copy().readwrite(ReadWrite.READ).offset(S.from_KiB(4)).size(S.from_KiB(4)).run([queue])
    assert_ios({
        'l0r' : 0, 'l0w' : 1,
        'l1r' : 0, 'l1w' : 1,
        'l2r' : 0, 'l2w' : 1,
        'cr'  : 1, 'cw'  : 0
    })

    # Single cache line read hit (L0)
    reset_stats()
    r.copy().readwrite(ReadWrite.READ).size(S.from_KiB(4)).run([queue])
    assert_ios({
        'l0r' : 1, 'l0w' : 0,
        'l1r' : 0, 'l1w' : 0,
        'l2r' : 0, 'l2w' : 0,
        'cr'  : 0, 'cw'  : 0
    })

    # Single cache line write hit (L0)
    reset_stats()
    r.copy().readwrite(ReadWrite.WRITE).size(S.from_KiB(4)).run([queue])
    assert_ios({
        'l0r' : 0, 'l0w' : 1,
        'l1r' : 0, 'l1w' : 1,
        'l2r' : 0, 'l2w' : 1,
        'cr'  : 0, 'cw'  : 1
    })

    # Trigger eviction from L0 by writing more than cache size
    r.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(60)).run([queue])

    # Single cache line read hit (L1)
    reset_stats()
    r.copy().readwrite(ReadWrite.READ).size(S.from_KiB(4)).run([queue])
    assert_ios({
        'l0r' : 0, 'l0w' : 1,
        'l1r' : 1, 'l1w' : 0,
        'l2r' : 0, 'l2w' : 0,
        'cr'  : 0, 'cw'  : 0
    })

    # Trigger eviction from L0 & L1 by writing more than cache size
    r.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(110)).run([queue])

    # Single cache line read hit (L2)
    reset_stats()
    r.copy().readwrite(ReadWrite.READ).size(S.from_KiB(4)).run([queue])
    assert_ios({
        'l0r' : 0, 'l0w' : 1,
        'l1r' : 0, 'l1w' : 1,
        'l2r' : 1, 'l2w' : 0,
        'cr'  : 0, 'cw'  : 0
    })


# TODO: What is the actual point of this? PyOCF is too slow for stress testing
#       and brute force race condition hunting. For those OCL TF should be better.
def test_stability(pyocf_ctx):
    # bombard the 2-level cache with IOs and close it immediately
    upper = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    lower = Cache.start_on_device(RamVolume(S.from_MiB(100)), metadata_volatile=True)

    lower.ml_add_cache(upper)

    core = Core.using_device(RamVolume(S.from_MiB(200)))
    lower.add_core(core)

    cfv = CoreVolume(core)
    cfv.open()

    q_count = len(upper.io_queues)
    length = 4096
    direction = IoDir.READ

    def send_ios():
        for i in range(1000):
            q = upper.io_queues[i % q_count]
            addr = length * i
            if cfv is None:
                break
            io = cfv.new_io(q, addr, length, direction, 0, 0)
            data = Data(length)
            io.set_data(data)
            cmpl = OcfCompletion([("err", c_int)])
            io.callback = cmpl.callback
            io.submit()

    thread = Thread(group=None, target=send_ios, name='io thread')
    thread.start()
    time.sleep(0.1)
    cfv = None
    thread.join()


def test_io_content(pyocf_ctx):
    cache1 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    cache2 = Cache.start_on_device(RamVolume(S.from_MiB(50)), metadata_volatile=True)
    core = Core.using_device(RamVolume(S.from_MiB(100)))
    cache1.ml_add_cache(cache2)
    cache1.add_core(core)

    core_sync_write(core, 4096, b'12345')
    data = core_sync_read(core, 4096, 5)
    assert data == b'12345'
