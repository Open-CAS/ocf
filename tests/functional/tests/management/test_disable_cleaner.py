#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest


@pytest.mark.skip(reason="not implemented")
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
    pass


@pytest.mark.skip(reason="not implemented")
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
    pass


@pytest.mark.skip(reason="not implemented")
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
    pass


@pytest.mark.skip(reason="not implemented")
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
    pass
