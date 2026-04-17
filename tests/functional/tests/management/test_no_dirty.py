#
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

from pyocf.utils import Size as S
from pyocf.types.cache import Cache, CacheMode, CleaningPolicy
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.rio import Rio, ReadWrite


def test_no_dirty_prevents_new_dirty_data(pyocf_ctx):
    cache = Cache.start_on_device(
        RamVolume(S.from_MiB(50)), cache_mode=CacheMode.WB, metadata_volatile=True
    )
    core = Core.using_device(RamVolume(S.from_MiB(100)))
    cache.add_core(core)
    cache.set_cleaning_policy(CleaningPolicy.NOP)

    cfv = CoreVolume(core)
    queue = cache.get_default_queue()
    r = Rio().target(cfv).bs(S.from_KiB(4))

    r.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(1)).run([queue])

    stats = cache.get_stats()
    dirty_before = stats["usage"]["dirty"]["value"]
    assert dirty_before > 0

    cache.set_no_dirty(True)

    r.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(1)).offset(S.from_MiB(1)).run([queue])

    stats = cache.get_stats()
    dirty_after = stats["usage"]["dirty"]["value"]
    assert dirty_after == dirty_before


def test_no_dirty_can_be_unset(pyocf_ctx):
    cache = Cache.start_on_device(
        RamVolume(S.from_MiB(50)), cache_mode=CacheMode.WB, metadata_volatile=True
    )
    core = Core.using_device(RamVolume(S.from_MiB(100)))
    cache.add_core(core)
    cache.set_cleaning_policy(CleaningPolicy.NOP)

    cfv = CoreVolume(core)
    queue = cache.get_default_queue()
    r = Rio().target(cfv).bs(S.from_KiB(4))

    cache.set_no_dirty(True)

    r.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(1)).run([queue])

    stats = cache.get_stats()
    dirty_while_set = stats["usage"]["dirty"]["value"]
    assert dirty_while_set == 0

    cache.set_no_dirty(False)

    r.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(1)).offset(S.from_MiB(1)).run([queue])

    stats = cache.get_stats()
    dirty_after_unset = stats["usage"]["dirty"]["value"]
    assert dirty_after_unset > 0


def test_no_dirty_stop_cache(pyocf_ctx):
    cache = Cache.start_on_device(
        RamVolume(S.from_MiB(50)), cache_mode=CacheMode.WB, metadata_volatile=True
    )
    core = Core.using_device(RamVolume(S.from_MiB(100)))
    cache.add_core(core)
    cache.set_cleaning_policy(CleaningPolicy.NOP)

    cfv = CoreVolume(core)
    queue = cache.get_default_queue()
    r = Rio().target(cfv).bs(S.from_KiB(4))

    r.copy().readwrite(ReadWrite.WRITE).size(S.from_MiB(1)).run([queue])

    cache.set_no_dirty(True)
    cache.flush()
    cache.stop()
