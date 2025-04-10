#
# Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from pyocf.ocf_utils import CoreContextManager, core_sync_read, core_sync_write


def test_write_two_addresses_same_hash(pyocf_ctx):
    # cache size = 40MB
    # number of cache lines = 40MB / 4KB = 10240
    # number of hash buckets = 10240 / 4 = 2560
    cache_size_mb = 40
    # to map to the same hash bucket, addresses should be exactly 2560 core
    # lines apart which are 10MB = 2560 * 4KB = cache size / 4.
    same_hash_delta = cache_size_mb * (1024**2) // 4
    with CoreContextManager(cache_size_mb, cache_size_mb*2,
                            metadata_volatile=True) \
            as core:
        # we write to two addresses that map to the same hash bucket
        core_sync_write(core, 1024 + same_hash_delta, b'abcdefgh')
        core_sync_write(core, 1024, b'1234567890')
        # let's read to verify successful write
        s = core_sync_read(core, 1024, 10)
        assert s == b'1234567890'
        s = core_sync_read(core, 1024 + same_hash_delta, 8)
        assert s == b'abcdefgh'
