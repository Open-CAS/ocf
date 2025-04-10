#
# Copyright(c) 2024 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest

from pyocf.utils import Size as S
from pyocf.types.cache import Cache, CacheMode, CleaningPolicy
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume, Volume
from pyocf.types.volume_core import CoreVolume
from pyocf.rio import Rio, ReadWrite


def test_flush_cache(pyocf_ctx):
    cache = Cache.start_on_device(
        RamVolume(S.from_MiB(50)),
        cache_mode=CacheMode.WB,
        metadata_volatile=True
    )
    core = Core.using_device(RamVolume(S.from_MiB(100)))

    cache.add_core(core)

    cache.set_cleaning_policy(CleaningPolicy.NOP)

    cfv = CoreVolume(core)
    queue = core.cache.get_default_queue()
    r = Rio().target(cfv).bs(S.from_KiB(4))

    r.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(10)).run([queue])

    stats = cache.get_stats()
    assert S.from_sector(stats["usage"]["dirty"]["value"]) == S.from_MiB(10)

    cache.flush()

    stats = cache.get_stats()
    assert S.from_sector(stats["usage"]["dirty"]["value"]) == S.from_MiB(0)


def test_flush_core(pyocf_ctx):
    cache = Cache.start_on_device(
        RamVolume(S.from_MiB(50)),
        cache_mode=CacheMode.WB,
        metadata_volatile=True
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
    assert S.from_sector(cache_stats["usage"]["dirty"]["value"]) == S.from_MiB(20)

    core1_stats = core1.get_stats()
    assert S.from_sector(core1_stats["usage"]["dirty"]["value"]) == S.from_MiB(10)

    core2_stats = core2.get_stats()
    assert S.from_sector(core2_stats["usage"]["dirty"]["value"]) == S.from_MiB(10)

    core1.flush()

    cache_stats = cache.get_stats()
    assert S.from_sector(cache_stats["usage"]["dirty"]["value"]) == S.from_MiB(10)

    core1_stats = core1.get_stats()
    assert S.from_sector(core1_stats["usage"]["dirty"]["value"]) == S.from_MiB(0)

    core2_stats = core2.get_stats()
    assert S.from_sector(core2_stats["usage"]["dirty"]["value"]) == S.from_MiB(10)

    core2.flush()

    cache_stats = cache.get_stats()
    assert S.from_sector(cache_stats["usage"]["dirty"]["value"]) == S.from_MiB(0)

    core1_stats = core1.get_stats()
    assert S.from_sector(core1_stats["usage"]["dirty"]["value"]) == S.from_MiB(0)

    core2_stats = core2.get_stats()
    assert S.from_sector(core2_stats["usage"]["dirty"]["value"]) == S.from_MiB(0)
