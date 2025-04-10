#
# Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import gc

from pyocf.types import logger
from pyocf.types import ctx
from pyocf.types import volume
from pyocf.ocf_utils import CoreContextManager, core_sync_read, core_sync_write, WriteMode

CACHE_SIZE_MB = 40
CORE_SIZE_MB = 50


def test_write_and_read(pyocf_ctx):
    with CoreContextManager(CACHE_SIZE_MB, CORE_SIZE_MB) as core:
        core_sync_write(core, 0, b'1234567890')
        s = core_sync_read(core, 0, 10)
        assert s == b'1234567890'


def test_write_and_partial_read(pyocf_ctx):
    with CoreContextManager(CACHE_SIZE_MB, CORE_SIZE_MB) as core:
        core_sync_write(core, 0, b'abcdefghijkl')
        s = core_sync_read(core, 3, 5)
        assert s == b'defgh'


def test_write_and_read_outside_after(pyocf_ctx):
    with CoreContextManager(CACHE_SIZE_MB, CORE_SIZE_MB) as core:
        core_sync_write(core, 0, b'abcdefghijkl')
        s = core_sync_read(core, 10, 10)
        assert s == b'kl\x00\x00\x00\x00\x00\x00\x00\x00'


def test_write_and_read_outside_before(pyocf_ctx):
    with CoreContextManager(CACHE_SIZE_MB, CORE_SIZE_MB) as core:
        core_sync_write(core, 10, b'abcdefghijkl')
        s = core_sync_read(core, 5, 10)
        assert s == b'\x00\x00\x00\x00\x00abcde'


def test_write_zero_pad(pyocf_ctx):
    with CoreContextManager(CACHE_SIZE_MB, CORE_SIZE_MB) as core:
        core_sync_write(core, 10, b'abcdefghijkl')
        core_sync_write(core, 13, b'1234', mode=WriteMode.ZERO_PAD)
        s = core_sync_read(core, 10, 10)
        core.cache.settle()
        assert s == b'\x00\x00\x001234\x00\x00\x00'
        stats = core.get_stats()
        # assert that only one READ took place
        assert stats['req']['rd_total']['value'] == 1
        assert stats['req']['wr_total']['value'] == 2


def test_write_read_modify_write(pyocf_ctx):
    with CoreContextManager(CACHE_SIZE_MB, CORE_SIZE_MB) as core:
        core_sync_write(core, 10, b'abcdefghijkl')
        core_sync_write(core, 13, b'1234', mode=WriteMode.READ_MODIFY_WRITE)
        s = core_sync_read(core, 10, 10)
        core.cache.settle()
        assert s == b'abc1234hij'
        stats = core.get_stats()
        # assert that two READs took place: one explicit,
        # and one implicit in the READ_MODIFY_WRITE operation
        assert stats['req']['rd_total']['value'] == 2
        assert stats['req']['wr_total']['value'] == 2


def test_pyocf_full_cycle():
    """
    runs a full cycle of initialization-io-finalization without injecting a
    pyocf_ctx from the outside
    """
    c = ctx.OcfCtx.with_defaults(logger.DefaultLogger(logger.LogLevel.WARN))
    c.register_volume_type(volume.RamVolume)
    c.register_volume_type(volume.ErrorDevice)
    try:
        with CoreContextManager(CACHE_SIZE_MB, CORE_SIZE_MB) as core:
            core_sync_write(core, 0, b'1234567890')
            s = core_sync_read(core, 0, 10)
            assert s == b'1234567890'
    finally:
        c.exit()
        gc.collect()
