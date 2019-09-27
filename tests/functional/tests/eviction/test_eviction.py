#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import logging
from ctypes import c_int

import pytest

from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.shared import OcfCompletion, CacheLineSize, SeqCutOffPolicy
from pyocf.types.volume import Volume
from pyocf.utils import Size

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize("mode", [CacheMode.WT, CacheMode.WB, CacheMode.WO])
@pytest.mark.xfail  # TODO: remove when fixed
def test_write_size_greater_than_cache(pyocf_ctx, mode: CacheMode, cls: CacheLineSize):
    """Test if eviction does not occur when IO greater than cache size is submitted.
    """
    cache_device = Volume(Size.from_MiB(20))  # this gives about 1.375 MiB actual caching space

    core_device = Volume(Size.from_MiB(5))
    cache = Cache.start_on_device(cache_device, cache_mode=mode,
                                  cache_line_size=cls)
    core_exported = Core.using_device(core_device)
    cache.add_core(core_exported)
    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    valid_io_size = Size.from_KiB(512)
    test_data = Data(valid_io_size)
    send_io(core_exported, test_data)

    stats = core_exported.cache.get_stats()
    assert stats["usage"]["occupancy"]["value"] == (valid_io_size.B / Size.from_KiB(4).B),\
        "Occupancy after first IO"
    prev_writes_to_core = stats["block"]["core_volume_wr"]["value"]

    # Anything below 5 MiB is a valid size (less than core device size)
    # Writing over 1.375 MiB in this case should go directly to core and shouldn't trigger eviction
    io_size_bigger_than_cache = Size.from_MiB(2)
    test_data = Data(io_size_bigger_than_cache)
    send_io(core_exported, test_data)

    stats = core_exported.cache.get_stats()

    # Writes from IO greater than cache size should go directly to core
    # Writes to core should equal the following:
    # Previous writes to core + size written + size cleaned (reads from cache)
    assert stats["block"]["core_volume_wr"]["value"] == \
        stats["block"]["cache_volume_rd"]["value"] + \
        prev_writes_to_core + io_size_bigger_than_cache.B / Size.from_KiB(4).B, \
        "Writes to core after second IO"

    # Occupancy shouldn't change (no eviction)
    assert stats["usage"]["occupancy"]["value"] == (valid_io_size.B / Size.from_KiB(4).B),\
        "Occupancy after second IO"


def send_io(exported_obj: Core, data: Data):
    io = exported_obj.new_io(
        exported_obj.cache.get_default_queue(),
        0, data.size, IoDir.WRITE, 0, 0
    )

    io.set_data(data)

    completion = OcfCompletion([("err", c_int)])
    io.callback = completion.callback
    io.submit()
    completion.wait()

    assert completion.results["err"] == 0, "IO to exported object completion"
