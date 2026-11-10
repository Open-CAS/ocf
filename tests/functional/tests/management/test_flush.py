#
# Copyright(c) 2024 Huawei Technologies Co., Ltd.
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

import random

import pytest

from pyocf.utils import Size as S
from pyocf.types.cache import Cache, CacheMode, CleaningPolicy
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume, TraceDevice, Volume
from pyocf.types.volume_core import CoreVolume
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.shared import CacheLineSize
from pyocf.rio import Rio, ReadWrite


def test_flush_cache(pyocf_ctx):
    cache = Cache.start_on_device(
        RamVolume(S.from_MiB(50)), cache_mode=CacheMode.WB, metadata_volatile=True
    )
    core = Core.using_device(RamVolume(S.from_MiB(100)))

    cache.add_core(core)

    cache.set_cleaning_policy(CleaningPolicy.NOP)

    cfv = CoreVolume(core)
    queue = core.cache.get_default_queue()
    r = Rio().target(cfv).bs(S.from_KiB(4))

    r.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(10)).run([queue])

    stats = cache.get_stats()
    assert S(stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(10)

    cache.flush()

    stats = cache.get_stats()
    assert S(stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(0)


def test_flush_core(pyocf_ctx):
    cache = Cache.start_on_device(
        RamVolume(S.from_MiB(50)), cache_mode=CacheMode.WB, metadata_volatile=True
    )
    core1 = Core.using_device(RamVolume(S.from_MiB(100)), name="core1")
    core2 = Core.using_device(RamVolume(S.from_MiB(100)), name="core2")

    cache.add_core(core1)
    cache.add_core(core2)

    cache.set_cleaning_policy(CleaningPolicy.NOP)

    cfv1 = CoreVolume(core1)
    cfv2 = CoreVolume(core2)
    queue = cache.get_default_queue()

    r1 = Rio().target(cfv1).bs(S.from_KiB(4))
    r2 = Rio().target(cfv2).bs(S.from_KiB(4))

    r1.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(10)).run([queue])
    r2.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(10)).run([queue])

    cache_stats = cache.get_stats()
    assert S(cache_stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(20)

    core1_stats = core1.get_stats()
    assert S(core1_stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(10)

    core2_stats = core2.get_stats()
    assert S(core2_stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(10)

    core1.flush()

    cache_stats = cache.get_stats()
    assert S(cache_stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(10)

    core1_stats = core1.get_stats()
    assert S(core1_stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(0)

    core2_stats = core2.get_stats()
    assert S(core2_stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(10)

    core2.flush()

    cache_stats = cache.get_stats()
    assert S(cache_stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(0)

    core1_stats = core1.get_stats()
    assert S(core1_stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(0)

    core2_stats = core2.get_stats()
    assert S(core2_stats["usage"]["dirty"]["value"] * 4096) == S.from_MiB(0)


def write_random(vol, queue, offset, size):
    content = random.randbytes(size)
    data = Data(size)
    data.write(content, size)
    vol.sync_io(queue, offset, data, IoDir.WRITE)
    return content


def dirty_bytes(stats):
    return S(stats["usage"]["dirty"]["value"] * 4096)


@pytest.mark.parametrize("cls", CacheLineSize)
def test_flush_more_than_one_portion(pyocf_ctx, cls):
    """
    A flush cleans the dirty data in portions of at most 100 MiB, collected while
    sweeping the cache lines. With more dirty data than that, every portion has to be
    flushed for the core to end up with the data held in the cache.
    """
    cache = Cache.start_on_device(
        RamVolume(S.from_MiB(400)),
        cache_mode=CacheMode.WB,
        cache_line_size=cls,
        metadata_volatile=True,
    )
    core_device = RamVolume(S.from_MiB(300))
    core = Core.using_device(core_device)
    cache.add_core(core)
    cache.set_cleaning_policy(CleaningPolicy.NOP)
    vol = CoreVolume(core)
    vol.open()
    queue = cache.get_default_queue()

    for mib in range(250):
        write_random(vol, queue, mib * S.from_MiB(1).B, S.from_MiB(1).B)
    assert dirty_bytes(cache.get_stats()) == S.from_MiB(250)

    cache.flush()

    assert dirty_bytes(cache.get_stats()) == S.from_MiB(0)
    assert cache.get_stats()["usage"]["occupancy"]["value"] > 0, "flush does not invalidate"
    # md5() of the exported object closes it - last
    assert core_device.md5() == vol.md5()


def test_flush_interleaved_cores(pyocf_ctx):
    """
    With the dirty lines of several cores interleaved in the cache, a core flush cleans
    only the lines of its core, and a cache flush - swept in slices concurrently, one
    per core with dirty data - cleans all of them.
    """
    cache = Cache.start_on_device(
        RamVolume(S.from_MiB(300)), cache_mode=CacheMode.WB, metadata_volatile=True
    )
    core_devices = [RamVolume(S.from_MiB(100)) for _ in range(4)]
    cores = [Core.using_device(dev, name=f"core{i}") for i, dev in enumerate(core_devices)]
    for core in cores:
        cache.add_core(core)
    cache.set_cleaning_policy(CleaningPolicy.NOP)
    vols = [CoreVolume(core) for core in cores]
    for vol in vols:
        vol.open()
    queue = cache.get_default_queue()

    for mib in range(40):
        for vol in vols:
            write_random(vol, queue, mib * S.from_MiB(1).B, S.from_MiB(1).B)
    assert dirty_bytes(cache.get_stats()) == S.from_MiB(160)

    cores[2].flush()

    for i, core in enumerate(cores):
        expected = S.from_MiB(0) if i == 2 else S.from_MiB(40)
        assert dirty_bytes(core.get_stats()) == expected
    assert dirty_bytes(cache.get_stats()) == S.from_MiB(120)

    cache.flush()

    assert dirty_bytes(cache.get_stats()) == S.from_MiB(0)
    for core in cores:
        assert dirty_bytes(core.get_stats()) == S.from_MiB(0)
    # md5() of the exported object closes it - last
    for dev, vol in zip(core_devices, vols):
        assert dev.md5() == vol.md5()


@pytest.mark.parametrize("cls", CacheLineSize)
def test_flush_contiguous_dirty_data_in_runs(pyocf_ctx, cls):
    """
    Contiguous dirty data is written to the core in runs of consecutive addresses, even if
    its cache lines are in a different order: the flush sweeps the hash table, where
    consecutive core lines are in consecutive buckets. A portion of buckets holds one range
    of core addresses per wrap of the core around the hash table (a quarter of the cache
    lines), so the writes are ascending runs, not one ascending sequence. Sparse dirty
    data elsewhere is flushed too.
    """
    pyocf_ctx.register_volume_type(TraceDevice)
    cache = Cache.start_on_device(
        RamVolume(S.from_MiB(200)),
        cache_mode=CacheMode.WB,
        cache_line_size=cls,
        metadata_volatile=True,
    )
    flushing = False
    writes = []

    def trace(vol, io_type, rw, addr, nbytes, flags):
        if flushing and io_type == TraceDevice.IoType.Data and rw == IoDir.WRITE:
            writes.append(addr)
        return True

    core_device = TraceDevice(RamVolume(S.from_MiB(300)), trace_fcn=trace)
    core = Core.using_device(core_device)
    cache.add_core(core)
    cache.set_cleaning_policy(CleaningPolicy.NOP)
    vol = CoreVolume(core)
    vol.open()
    queue = cache.get_default_queue()
    line = int(cls)

    # 60 MiB written line by line in random order, so that the cache lines are allocated in
    # an order unrelated to the core addresses
    written = {}
    dense = list(range(0, S.from_MiB(60).B, line))
    random.shuffle(dense)
    for addr in dense:
        written[addr] = write_random(vol, queue, addr, line)
    # a few lines elsewhere
    sparse = random.sample(range(S.from_MiB(200).B, S.from_MiB(300).B, line), 16)
    for addr in sparse:
        written[addr] = write_random(vol, queue, addr, line)

    flushing = True
    cache.flush()
    flushing = False

    assert dirty_bytes(cache.get_stats()) == S.from_MiB(0)
    dense_writes = [addr for addr in writes if addr < S.from_MiB(100).B]
    assert sorted(dense_writes) == list(range(0, S.from_MiB(60).B, line)), "every dense line written once"
    adjacent = sum(1 for a, b in zip(dense_writes, dense_writes[1:]) if b == a + line)
    assert adjacent >= 0.9 * (len(dense_writes) - 1), "contiguous data written in runs"
    assert sorted(addr for addr in writes if addr >= S.from_MiB(200).B) == sorted(sparse)
    core_bytes = core_device.vol.get_bytes()
    assert all(core_bytes[addr : addr + line] == content for addr, content in written.items())

