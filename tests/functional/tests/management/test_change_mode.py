#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import pytest

from pyocf.types.cache import Cache, CacheMode
from pyocf.types.volume import Volume
from pyocf.utils import Size as S
from pyocf.types.shared import CacheLineSize


@pytest.mark.parametrize("from_cm", CacheMode)
@pytest.mark.parametrize("to_cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
def test_change_cache_mode(pyocf_ctx, from_cm, to_cm, cls):
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(
        cache_device, cache_mode=from_cm, cache_line_size=cls
    )

    # Check if started with correct cache mode
    stats = cache.get_stats()
    assert stats["conf"]["cache_mode"] == from_cm

    # Change cache mode and check if stats are as expected
    cache.change_cache_mode(to_cm)
    stats_after = cache.get_stats()
    assert stats_after["conf"]["cache_mode"] == to_cm
