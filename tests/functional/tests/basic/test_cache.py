#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from pyocf.types.cache import Cache


# bug description: if cache is initialized without management queue, then
#                  cache.stop() fails
def test_bug_in_class_Cache(pyocf_ctx):
    cache = Cache(pyocf_ctx)
    cache.start_cache(init_mngmt_queue=False)
    cache.stop()
