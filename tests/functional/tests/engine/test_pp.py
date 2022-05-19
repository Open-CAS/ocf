#
# Copyright(c) 2019-2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import c_int
import pytest
import math
from datetime import timedelta

from pyocf.types.cache import Cache, PromotionPolicy, NhitParams
from pyocf.types.core import Core
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.utils import Size
from pyocf.types.shared import OcfCompletion
from pyocf.rio import Rio, ReadWrite


@pytest.mark.parametrize("promotion_policy", PromotionPolicy)
def test_init_nhit(pyocf_ctx, promotion_policy):
    """
    Check if starting cache with promotion policy is reflected in stats

    1. Create core/cache pair with parametrized promotion policy
    2. Get cache statistics
        * verify that promotion policy type is properly reflected in stats
    """

    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(cache_device, promotion_policy=promotion_policy)
    core = Core.using_device(core_device)

    cache.add_core(core)

    assert cache.get_stats()["conf"]["promotion_policy"] == promotion_policy


def test_change_to_nhit_and_back_io_in_flight(pyocf_ctx):
    """
    Try switching promotion policy during io, no io's should return with error

    1. Create core/cache pair with promotion policy ALWAYS
    2. Issue IOs without waiting for completion
    3. Change promotion policy to NHIT
    4. Wait for IO completions
        * no IOs should fail
    5. Issue IOs without waiting for completion
    6. Change promotion policy to ALWAYS
    7. Wait for IO completions
        * no IOs should fail
    """

    # Step 1
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)

    cache.add_core(core)
    vol = CoreVolume(core, open=True)
    queue = cache.get_default_queue()

    # Step 2
    r = (
        Rio()
        .target(vol)
        .njobs(10)
        .bs(Size.from_KiB(4))
        .readwrite(ReadWrite.RANDWRITE)
        .size(core_device.size)
        .time_based()
        .time(timedelta(minutes=1))
        .qd(10)
        .run_async([queue])
    )

    # Step 3
    cache.set_promotion_policy(PromotionPolicy.NHIT)

    # Step 4
    r.abort()
    assert r.error_count == 0, "No IO's should fail when turning NHIT policy on"

    # Step 5
    r.run_async([queue])

    # Step 6
    cache.set_promotion_policy(PromotionPolicy.ALWAYS)

    # Step 7
    r.abort()
    assert r.error_count == 0, "No IO's should fail when turning NHIT policy off"


def fill_cache(cache, fill_ratio):
    """
    Helper to fill cache from LBA 0.
    TODO:
        * make it generic and share across all tests
        * reasonable error handling
    """

    cache_lines = cache.get_stats()["conf"]["size"]

    bytes_to_fill = Size(round(cache_lines.bytes * fill_ratio))

    core = cache.cores[0]
    vol = CoreVolume(core, open=True)
    queue = cache.get_default_queue()

    r = (
        Rio()
        .target(vol)
        .readwrite(ReadWrite.RANDWRITE)
        .size(bytes_to_fill)
        .bs(Size(512))
        .qd(10)
        .run([queue])
    )


@pytest.mark.parametrize("fill_percentage", [0, 1, 50, 99])
@pytest.mark.parametrize("insertion_threshold", [2, 8])
def test_promoted_after_hits_various_thresholds(pyocf_ctx, insertion_threshold, fill_percentage):
    """
    Check promotion policy behavior with various set thresholds

    1. Create core/cache pair with promotion policy NHIT
    2. Set TRIGGER_THRESHOLD/INSERTION_THRESHOLD to predefined values
    3. Fill cache from the beggining until occupancy reaches TRIGGER_THRESHOLD%
    4. Issue INSERTION_THRESHOLD - 1 requests to core line not inserted to cache
        * occupancy should not change
    5. Issue one request to LBA from step 4
        * occupancy should rise by one cache line
    """

    # Step 1
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(cache_device, promotion_policy=PromotionPolicy.NHIT)
    core = Core.using_device(core_device)
    cache.add_core(core)
    vol = CoreVolume(core, open=True)
    queue = cache.get_default_queue()

    # Step 2
    cache.set_promotion_policy_param(
        PromotionPolicy.NHIT, NhitParams.TRIGGER_THRESHOLD, fill_percentage
    )
    cache.set_promotion_policy_param(
        PromotionPolicy.NHIT, NhitParams.INSERTION_THRESHOLD, insertion_threshold
    )
    # Step 3
    fill_cache(cache, fill_percentage / 100)

    cache.settle()
    stats = cache.get_stats()
    cache_lines = stats["conf"]["size"]
    assert stats["usage"]["occupancy"]["fraction"] // 10 == fill_percentage * 10
    filled_occupancy = stats["usage"]["occupancy"]["value"]

    # Step 4
    last_core_line = Size(int(core_device.size) - cache_lines.line_size)
    r = (
        Rio()
        .readwrite(ReadWrite.WRITE)
        .bs(Size(4096))
        .offset(last_core_line)
        .target(vol)
        .size(Size(4096) + last_core_line)
    )

    for i in range(insertion_threshold - 1):
        r.run([queue])

    cache.settle()
    stats = cache.get_stats()
    threshold_reached_occupancy = stats["usage"]["occupancy"]["value"]
    assert threshold_reached_occupancy == filled_occupancy, (
        "No insertion should occur while NHIT is triggered and core line ",
        "didn't reach INSERTION_THRESHOLD",
    )

    # Step 5
    r.run([queue])

    cache.settle()
    stats = cache.get_stats()
    assert (
        threshold_reached_occupancy == stats["usage"]["occupancy"]["value"] - 1
    ), "Previous request should be promoted and occupancy should rise"


def test_partial_hit_promotion(pyocf_ctx):
    """
    Check if NHIT promotion policy doesn't prevent partial hits from getting
    promoted to cache

    1. Create core/cache pair with promotion policy ALWAYS
    2. Issue one-sector IO to cache to insert partially valid cache line
    3. Set NHIT promotion policy with trigger=0 (always triggered) and high
    insertion threshold
    4. Issue a request containing partially valid cache line and next cache line
        * occupancy should rise - partially hit request should bypass nhit criteria
    """

    # Step 1
    cache_device = RamVolume(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(cache_device)
    core = Core.using_device(core_device)
    cache.add_core(core)
    vol = CoreVolume(core, open=True)
    queue = cache.get_default_queue()

    # Step 2
    r = Rio().readwrite(ReadWrite.READ).bs(Size(512)).size(Size(512)).target(vol).run([queue])

    stats = cache.get_stats()
    cache_lines = stats["conf"]["size"]
    assert stats["usage"]["occupancy"]["value"] == 1

    # Step 3
    cache.set_promotion_policy(PromotionPolicy.NHIT)
    cache.set_promotion_policy_param(PromotionPolicy.NHIT, NhitParams.TRIGGER_THRESHOLD, 0)
    cache.set_promotion_policy_param(PromotionPolicy.NHIT, NhitParams.INSERTION_THRESHOLD, 100)

    # Step 4
    req_size = Size(2 * cache_lines.line_size)
    r.size(req_size).bs(req_size).readwrite(ReadWrite.WRITE).run([queue])

    cache.settle()
    stats = cache.get_stats()
    assert stats["usage"]["occupancy"]["value"] == 2, "Second cache line should be mapped"
