#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
from pyocf.types.volume import RamVolume
from pyocf.types.cache import Cache, CacheMetadataSegment, CleaningPolicy
from pyocf.types.core import Core
from pyocf.types.shared import OcfError, OcfCompletion
from pyocf.utils import Size as S
from pyocf.helpers import get_metadata_segment_size
from ctypes import c_int

def test_attach_cleaner_disabled(pyocf_ctx):
    """
    title: Attach cache with cleaner_disabled option set.
    description: |
      Check that cache can be attached when cleaner_disabled option is
      selected and that "cleaning" metadata section is not allocated.
    pass_criteria:
      - Cache attaches properly.
      - The "cleaning" metadata section is not allocated.
      - Cache stops properly.
    steps:
      - Start the cache with default config.
      - Prepare default attach config and set cleaner_disabled field to true.
      - Attach cache device using prepared config.
      - Verify that cache was attached properly.
      - Verify that "cleaning" metadata section was not allocated.
      - Stop the cache.
      - Verify that the cache stopped properly.
    requirements:
      - disable_cleaner::set_cleaner_disabled
      - disable_cleaner::cleaning_section_alocation
    """
    cache_device = RamVolume(S.from_MiB(50))
    core_device = RamVolume(S.from_MiB(10))

    cache = Cache.start_on_device(cache_device, disable_cleaner=True)
    core = Core.using_device(core_device)

    stats = cache.get_stats()
    assert stats["conf"]["attached"] is True, "checking whether cache is attached properly"

    cleaning_size = get_metadata_segment_size(cache, CacheMetadataSegment.CLEANING)
    assert (
        cleaning_size == 0
    ), f'Metadata cleaning segment size expected: "0", got: "{cleaning_size}"'

    cache.stop()
    assert Cache.get_by_name("cache1", pyocf_ctx) != 0, "Try getting cache after stopping it"


def test_load_cleaner_disabled(pyocf_ctx):
    """
    title: Load cache in cleaner_disabled mode.
    description: |
      Check that loading the cache that was previously attached with
      cleaner_disabled option preserves cleaner_disabled setting.
    pass_criteria:
      - Cache loads properly.
      - The "cleaning" metadata section is not allocated.
      - Cache stops properly.
    steps:
      - Start the cache with default config.
      - Prepare default attach config and set cleaner_disabled field to true.
      - Attach cache device using prepared config.
      - Stop the cache.
      - Load the cache.
      - Verify that cache was loaded properly.
      - Verify that "cleaning" metadata section was not allocated.
      - Stop the cache.
      - Verify that the cache stopped properly.
    requirements:
      - disable_cleaner::load_cleaner_disabled
      - disable_cleaner::cleaning_section_alocation
    """
    cache_device = RamVolume(S.from_MiB(50))
    core_device = RamVolume(S.from_MiB(10))

    cache = Cache.start_on_device(cache_device, disable_cleaner=True)
    core = Core.using_device(core_device)

    cache.add_core(core)

    cache.stop()

    cache = Cache.load_from_device(cache_device, open_cores=False, disable_cleaner=True)

    cache.add_core(core, try_add=True)

    stats = cache.get_stats()
    assert stats["conf"]["attached"] is True, "checking whether cache is attached properly"

    cleaning_size = get_metadata_segment_size(cache, CacheMetadataSegment.CLEANING)
    assert (
        cleaning_size == 0
    ), f'Metadata cleaning segment size expected: "0", got: "{cleaning_size}"'

    cache.stop()
    assert Cache.get_by_name("cache1", pyocf_ctx) != 0, "Try getting cache after stopping it"



def test_cleaner_disabled_nop(pyocf_ctx):
    """
    title: NOP enfocement in cleaner_disabled mode..
    description: |
      Check that after attaching cache with cleaner_diabled option set, the
      cleaning policy is by default set to NOP and that it is not possible
      to change it.
    pass_criteria:
      - Cleaning policy is set to NOP after cache attach.
      - It is not possible to change cleaning policy to other than NOP.
    steps:
      - Start the cache with default config.
      - Prepare default attach config and set cleaner_disabled field to true.
      - Attach cache device using prepared config.
      - Verify that cleaning policy is NOP.
      - Try to set cleaning policy to [ALRU, ACP] and verify that operation failed.
      - Try to set cleaning policy to NOP and verify that operation succeeded.
      - Stop the cache.
    requirements:
      - disable_cleaner::starting_with_nop_policy
      - disable_cleaner::nop_enforcement
    """
    cache_device = RamVolume(S.from_MiB(50))

    cache = Cache.start_on_device(cache_device, disable_cleaner=True)

    assert cache.get_cleaning_policy() == CleaningPolicy.NOP, (
        "Cleaning policy should be NOP after starting cache with disabled cleaner"
    )

    with pytest.raises(OcfError):
        cache.set_cleaning_policy(CleaningPolicy.ALRU)

    assert cache.get_cleaning_policy() == CleaningPolicy.NOP, (
        "It shouldn't be possible to switch cleaning policy to ALRU when cleaner is disabled"
    )

    with pytest.raises(OcfError):
        cache.set_cleaning_policy(CleaningPolicy.ACP)

    assert cache.get_cleaning_policy() == CleaningPolicy.NOP, (
        "It shouldn't be possible to switch cleaning policy to ACP when cleaner is disabled"
    )

    cache.set_cleaning_policy(CleaningPolicy.NOP)


def test_attach_cleaner_disabled_non_default(pyocf_ctx):
    """
    title: Attach cache with default config does not set clener_disabled.
    description: |
      Check that when attaching cache with default attach config the
      cleaner_disabled option is not selected.
    pass_criteria:
      - Cache attaches properly.
      - The "cleaning" metadata section is not allocated.
      - Cache stops properly.
    steps:
      - Start the cache with default config.
      - Attach cache device using default config.
      - Verify that "cleaning" metadata section was allocated.
      - Stop the cache.
    requirements:
      - disable_cleaner::default_setting
    """
    cache_device = RamVolume(S.from_MiB(50))

    cache = Cache.start_on_device(cache_device)

    cleaning_size = get_metadata_segment_size(cache, CacheMetadataSegment.CLEANING)
    assert (
        cleaning_size > 0
    ), f'Metadata cleaning segment size expected: "> 0", got: "{cleaning_size}"'
