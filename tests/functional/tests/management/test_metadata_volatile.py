#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
from pyocf.rio import Rio, ReadWrite
from pyocf.types.cache import Cache, CacheMode, CleaningPolicy, SeqCutOffPolicy
from pyocf.types.core import Core
from pyocf.types.io import IoDir
from pyocf.types.shared import OcfError
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size as S


def test_attach_metadata_volatile(pyocf_ctx):
    """
    title: Attach cache with metadata_volatile option set.
    description: |
      Check that cache can be attached when metadata_volatile option is
      selected and that metadata does not occupy any space on the cache
      volume.
    pass_criteria:
      - Cache attaches properly.
      - All the cache capacity is available as cache lines.
      - Cache stops properly.
    steps:
      - Start the cache with metadata_volatile option set config.
      - Attach cache device.
      - Verify that cache was attached properly.
      - Verify that cache size in statistics is equal cache volume size.
      - Stop the cache.
      - Verify that the cache stopped properly.
    """
    cache_device = RamVolume(S.from_MiB(50))

    cache = Cache.start_on_device(cache_device, metadata_volatile=True)
    stats = cache.get_stats()
    assert stats["conf"]["size"] == cache_device.get_length()
    cache.stop()


def test_load_metadata_volatile(pyocf_ctx):
    """
    title: Try to load cache with metadata_volatile option set.
    description: |
      Check that it is not possible to load cache that was previously
      started with metadata_volatile option set.
      volume.
    pass_criteria:
      - Cache does not load.
    steps:
      - Start the cache with metadata_volatile option set config.
      - Attach cache device.
      - Stop the cache.
      - Try to load the cache.
      - Verify that the cache did not load and the reason is missing metadata.
    """
    cache_device = RamVolume(S.from_MiB(50))

    cache = Cache.start_on_device(cache_device, metadata_volatile=True)
    cache.stop()
    with pytest.raises(OcfError, match="OCF_ERR_NO_METADATA"):
        cache = Cache.load_from_device(cache_device)


def test_metadata_volatile_io(pyocf_ctx):
    """
    title: |
      Test if in metadata_volatile mode there are no metadata writes to
      the cache volume during io.
    description: |
      Check that cache started with metadata_volatile option set does not
      try to write metadata to the cache volume during io operations.
    pass_criteria:
      - No metadata writes to the cache volume detacted.
    steps:
      - Start the cache with metadata_volatile option set config.
      - Attach cache device.
      - Set the cache mode to Write-Back.
      - Add one core.
      - Issue writes to the core that.
      - Verify if number of writes to the cache volume is equal number
        of the cache lines inserted.
      - Stop the cache.
    """
    cache_device = RamVolume(S.from_MiB(50))
    core_device = RamVolume(S.from_MiB(20))

    cache = Cache.start_on_device(cache_device, metadata_volatile=True)
    cache.change_cache_mode(CacheMode.WB)
    core = Core.using_device(core_device, name="test_core")
    cache.add_core(core)
    vol = CoreVolume(core, open=True)

    r = (
        Rio()
        .target(vol)
        .bs(S.from_KiB(4))
        .readwrite(ReadWrite.WRITE)
        .size(core_device.get_length())
    )

    r.run([cache.get_default_queue()])

    assert cache_device.get_stats()[IoDir.WRITE] == core_device.size.blocks_4k

    cache.stop()


def test_metadata_volatile_management_io(pyocf_ctx):
    """
    title: |
      Test if management operations write to the cache volume
      in metadata_volatile mode.
    description: |
      Check that no write to the cache volume occurs when management operation
      is issued on the cache that was started with metadata_volatile option set.
    pass_criteria:
      - No writes to the cache volume occur.
    steps:
      - Start the cache with metadata_volatile option set config.
      - Attach cache device.
      - Verify if there is zero writes to the cache volume.
      - Add one core.
      - Verify if there is zero writes to the cache volume.
      - Change the cache mode.
      - Verify if there is zero writes to the cache volume.
      - Set the cleaning policy.
      - Verify if there is zero writes to the cache volume.
      - Set the sequential cutoff policy.
      - Verify if there is zero writes to the cache volume.
      - Remove the core.
      - Verify if there is zero writes to the cache volume.
      - Stop the cache.
      - Verify if there is zero writes to the cache volume.
    """
    cache_device = RamVolume(S.from_MiB(50))
    core_device = RamVolume(S.from_MiB(20))

    cache = Cache.start_on_device(cache_device, metadata_volatile=True)
    assert cache_device.get_stats()[IoDir.WRITE] == 0

    core = Core.using_device(core_device, name="test_core")
    cache.add_core(core)
    assert cache_device.get_stats()[IoDir.WRITE] == 0

    cache.change_cache_mode(CacheMode.WB)
    assert cache_device.get_stats()[IoDir.WRITE] == 0

    cache.set_cleaning_policy(CleaningPolicy.ACP)
    assert cache_device.get_stats()[IoDir.WRITE] == 0

    cache.set_seq_cut_off_policy(SeqCutOffPolicy.ALWAYS)
    assert cache_device.get_stats()[IoDir.WRITE] == 0

    cache.remove_core(core)
    assert cache_device.get_stats()[IoDir.WRITE] == 0

    cache.stop()
    assert cache_device.get_stats()[IoDir.WRITE] == 0
