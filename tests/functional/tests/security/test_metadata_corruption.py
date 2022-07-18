#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
from datetime import timedelta
import logging
from random import randrange
from contextlib import nullcontext, suppress
from enum import Enum

from pyocf.types.volume import RamVolume
from pyocf.types.volume_replicated import ReplicatedVolume
from pyocf.types.cache import Cache, CacheMetadataSegment, CacheMode
from pyocf.types.volume_cache import CacheVolume
from pyocf.types.core import Core
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size
from pyocf.types.shared import CacheLineSize, OcfError, OcfErrorCode
from pyocf.types.ctx import OcfCtx
from pyocf.rio import Rio, ReadWrite
from pyocf.helpers import (
    get_metadata_segment_size,
    get_metadata_segment_elems_count,
    get_metadata_segment_elems_per_page,
    get_metadata_segment_elem_size,
    get_metadata_segment_is_flapped,
    get_metadata_segment_page_location,
)

logger = logging.getLogger(__name__)


def raises(exception):
    context = pytest.raises(exception)
    context.__name__ = f"Raises({exception.__name__})"

    return context


def does_not_raise():
    context = nullcontext()
    context.__name__ = "DoesNotRaise"

    return context


def may_raise(exception):
    context = suppress(exception)
    context.__name__ = f"MayRaise({exception.__name__})"

    return context


class Shutdown(Enum):
    DIRTY = True
    CLEAN = False


@pytest.mark.security
@pytest.mark.parametrize(
    "shutdown_type,target_segment,expectation",
    [
        (Shutdown.DIRTY, CacheMetadataSegment.SB_CONFIG, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.SB_RUNTIME, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.RESERVED, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.PART_CONFIG, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.PART_RUNTIME, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.CORE_CONFIG, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.CORE_RUNTIME, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.CORE_UUID, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.CLEANING, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.LRU, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.COLLISION, may_raise(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.LIST_INFO, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.HASH, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.SB_CONFIG, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.SB_RUNTIME, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.RESERVED, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.PART_CONFIG, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.PART_RUNTIME, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.CORE_CONFIG, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.CORE_RUNTIME, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.CORE_UUID, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.CLEANING, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.LRU, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.COLLISION, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.LIST_INFO, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.HASH, raises(OcfError)),
    ],
)
@pytest.mark.parametrize("cache_line_size", CacheLineSize)
@pytest.mark.parametrize("cache_mode", CacheMode)
def test_metadata_corruption(
    pyocf_ctx, cache_line_size, cache_mode, shutdown_type, target_segment, expectation
):
    cache_volume = RamVolume(Size.from_MiB(60))

    core_volume = RamVolume(Size.from_MiB(1))

    cache = Cache.start_on_device(
        cache_volume,
        cache_mode=cache_mode,
        cache_line_size=cache_line_size,
    )

    corrupted_bytes = get_random_target_in_segment(cache, target_segment)

    core = Core(core_volume)
    cache.add_core(core)

    core_exp_volume = CoreVolume(core)
    queue = cache.get_default_queue()

    r = (
        Rio()
        .target(core_exp_volume)
        .njobs(1)
        .readwrite(ReadWrite.WRITE)
        .size(Size.from_MiB(1))
        .qd(1)
        .run([queue])
    )

    if shutdown_type == Shutdown.DIRTY:
        cache.save()
        cache.device.offline()

    exc = False
    try:
        cache.stop()
    except OcfError:
        exc = True

    cache_volume.online()

    if shutdown_type == Shutdown.DIRTY:
        assert exc, "Stopping with device offlined should raise an exception"

    for byte in corrupted_bytes:
        corrupt_byte(cache_volume.data, byte)

    with expectation:
        cache = Cache.load_from_device(cache_volume)


@pytest.mark.security
@pytest.mark.parametrize(
    "shutdown_type,target_segment,expectation",
    [
        (Shutdown.DIRTY, CacheMetadataSegment.SB_CONFIG, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.SB_RUNTIME, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.RESERVED, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.PART_CONFIG, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.PART_RUNTIME, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.CORE_CONFIG, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.CORE_RUNTIME, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.CORE_UUID, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.CLEANING, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.LRU, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.COLLISION, may_raise(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.LIST_INFO, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.HASH, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.SB_CONFIG, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.SB_RUNTIME, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.RESERVED, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.PART_CONFIG, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.PART_RUNTIME, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.CORE_CONFIG, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.CORE_RUNTIME, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.CORE_UUID, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.CLEANING, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.LRU, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.COLLISION, may_raise(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.LIST_INFO, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.HASH, does_not_raise()),
    ],
)
@pytest.mark.parametrize("cache_line_size", CacheLineSize)
@pytest.mark.parametrize("cache_mode", CacheMode)
def test_metadata_corruption_standby_activate(
    pyocf_2_ctx, cache_line_size, cache_mode, shutdown_type, target_segment, expectation
):
    primary_ctx, secondary_ctx = pyocf_2_ctx

    primary_cache_volume = RamVolume(Size.from_MiB(60))
    secondary_cache_volume = RamVolume(Size.from_MiB(60))

    core_volume = RamVolume(Size.from_MiB(1))

    secondary_cache = Cache(
        owner=secondary_ctx,
        cache_mode=cache_mode,
        cache_line_size=cache_line_size,
    )
    secondary_cache.start_cache()
    secondary_cache.standby_attach(secondary_cache_volume)

    corrupted_bytes = get_random_target_in_segment(secondary_cache, target_segment)

    secondary_cache_exp_obj = CacheVolume(secondary_cache)
    primary_cache_replicated_volume = ReplicatedVolume(
        primary_cache_volume, secondary_cache_exp_obj
    )

    primary_cache = Cache.start_on_device(
        primary_cache_replicated_volume,
        owner=primary_ctx,
        cache_mode=cache_mode,
        cache_line_size=cache_line_size,
    )
    core = Core(core_volume)
    primary_cache.add_core(core)

    core_exp_volume = CoreVolume(core)
    queue = primary_cache.get_default_queue()

    r = (
        Rio()
        .target(core_exp_volume)
        .njobs(1)
        .readwrite(ReadWrite.WRITE)
        .size(Size.from_MiB(1))
        .qd(1)
        .run([queue])
    )

    if shutdown_type == Shutdown.DIRTY:
        primary_cache.save()
        primary_cache.device.offline()

    exc = False
    try:
        primary_cache.stop()
    except OcfError:
        exc = True

    primary_cache_replicated_volume.online()

    secondary_cache.standby_detach()

    if shutdown_type == Shutdown.DIRTY:
        assert exc, "Stopping with device offlined should raise an exception"

    for byte in corrupted_bytes:
        corrupt_byte(secondary_cache_volume.data, byte)

    with expectation:
        secondary_cache.standby_activate(secondary_cache_volume, open_cores=False)


@pytest.mark.security
@pytest.mark.parametrize(
    "shutdown_type,target_segment,expectation",
    [
        (Shutdown.DIRTY, CacheMetadataSegment.SB_CONFIG, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.SB_RUNTIME, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.RESERVED, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.PART_CONFIG, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.PART_RUNTIME, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.CORE_CONFIG, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.CORE_RUNTIME, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.CORE_UUID, raises(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.CLEANING, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.LRU, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.COLLISION, may_raise(OcfError)),
        (Shutdown.DIRTY, CacheMetadataSegment.LIST_INFO, does_not_raise()),
        (Shutdown.DIRTY, CacheMetadataSegment.HASH, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.SB_CONFIG, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.SB_RUNTIME, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.RESERVED, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.PART_CONFIG, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.PART_RUNTIME, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.CORE_CONFIG, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.CORE_RUNTIME, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.CORE_UUID, raises(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.CLEANING, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.LRU, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.COLLISION, may_raise(OcfError)),
        (Shutdown.CLEAN, CacheMetadataSegment.LIST_INFO, does_not_raise()),
        (Shutdown.CLEAN, CacheMetadataSegment.HASH, does_not_raise()),
    ],
)
@pytest.mark.parametrize("cache_line_size", CacheLineSize)
@pytest.mark.parametrize("cache_mode", CacheMode)
def test_metadata_corruption_standby_load(
    pyocf_2_ctx, cache_line_size, cache_mode, shutdown_type, target_segment, expectation
):
    primary_ctx, secondary_ctx = pyocf_2_ctx

    primary_cache_volume = RamVolume(Size.from_MiB(60))
    secondary_cache_volume = RamVolume(Size.from_MiB(60))

    core_volume = RamVolume(Size.from_MiB(1))

    secondary_cache = Cache(
        owner=secondary_ctx,
        cache_mode=cache_mode,
        cache_line_size=cache_line_size,
    )
    secondary_cache.start_cache()
    secondary_cache.standby_attach(secondary_cache_volume)

    corrupted_bytes = get_random_target_in_segment(secondary_cache, target_segment)

    secondary_cache_exp_obj = CacheVolume(secondary_cache)
    primary_cache_replicated_volume = ReplicatedVolume(
        primary_cache_volume, secondary_cache_exp_obj
    )

    primary_cache = Cache.start_on_device(
        primary_cache_replicated_volume,
        owner=primary_ctx,
        cache_mode=cache_mode,
        cache_line_size=cache_line_size,
    )
    core = Core(core_volume)
    primary_cache.add_core(core)

    core_exp_volume = CoreVolume(core)
    queue = primary_cache.get_default_queue()

    r = (
        Rio()
        .target(core_exp_volume)
        .njobs(1)
        .readwrite(ReadWrite.WRITE)
        .size(Size.from_MiB(1))
        .qd(1)
        .run([queue])
    )

    if shutdown_type == Shutdown.DIRTY:
        primary_cache.save()
        primary_cache.device.offline()

    exc = False
    try:
        primary_cache.stop()
    except OcfError:
        exc = True

    primary_cache_replicated_volume.online()

    secondary_cache.stop()

    if shutdown_type == Shutdown.DIRTY:
        assert exc, "Stopping with device offlined should raise an exception"

    for byte in corrupted_bytes:
        corrupt_byte(secondary_cache_volume.data, corrupted_bytes)

    loaded = False
    with expectation:
        secondary_cache = Cache.load_standby_from_device(
            secondary_cache_volume, secondary_ctx, cache_line_size=cache_line_size
        )
        loaded = True

    if loaded:
        secondary_cache.standby_detach()

        secondary_cache.standby_activate(secondary_cache_volume, open_cores=False)


def corrupt_byte(buffer, offset):
    logger.info(f"Corrupting byte {offset}")
    byte_val = int.from_bytes(buffer[offset], "big")
    target_val = byte_val ^ 0xAA
    buffer[offset] = (target_val).to_bytes(1, "big")
    logger.debug(f"0x{byte_val:02X} -> 0x{target_val:02X}")


def get_random_target_in_segment(cache: Cache, target_segment: CacheMetadataSegment):
    offset = Size.from_page(get_metadata_segment_page_location(cache, target_segment))
    page_count = get_metadata_segment_size(cache, target_segment)
    if get_metadata_segment_is_flapped(cache, target_segment):
        page_count = page_count // 2
    elem_size = get_metadata_segment_elem_size(cache, target_segment)
    elems_per_page = get_metadata_segment_elems_per_page(cache, target_segment)
    elems_count = get_metadata_segment_elems_count(cache, target_segment)

    target_page = randrange(0, page_count) if page_count > 1 else 0

    if target_page != page_count - 1:
        page_filled = elem_size * elems_per_page
    else:
        page_filled = (elems_count % elems_per_page) * elem_size

    offset_in_page = randrange(0, page_filled) if page_filled else 0

    corrupted_byte = target_page * Size.from_page(1).B + offset_in_page + offset.B

    if get_metadata_segment_is_flapped(cache, target_segment):
        ret = (corrupted_byte, corrupted_byte + (page_count * Size.from_page(1).B))
    else:
        ret = (corrupted_byte,)

    return ret
