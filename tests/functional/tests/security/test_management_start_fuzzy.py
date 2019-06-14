#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import pytest
import logging
from tests.utils import generate_random_numbers
from pyocf.types.cache import Cache, CacheMode, EvictionPolicy, MetadataLayout
from pyocf.types.volume import Volume
from pyocf.utils import Size
from pyocf.types.shared import OcfError, CacheLineSize
from ctypes import c_uint32

logger = logging.getLogger(__name__)


def try_start_cache(**config):
    cache_device = Volume(Size.from_MiB(30))
    cache = Cache.start_on_device(cache_device, **config)
    cache.stop()


@pytest.mark.security
@pytest.mark.parametrize("cls", CacheLineSize)
def test_fuzzy_start_cache_mode(pyocf_ctx, cls, c_uint32_randomize):
    """
    Test whether it is impossible to start cache with invalid cache mode value.
    :param pyocf_ctx: basic pyocf context fixture
    :param cls: cache line size value to start cache with
    :param c_uint32_randomize: cache mode enum value to start cache with
    """
    if c_uint32_randomize not in [item.value for item in CacheMode]:
        with pytest.raises(OcfError, match="OCF_ERR_INVALID_CACHE_MODE"):
            try_start_cache(cache_mode=c_uint32_randomize, cache_line_size=cls)
    else:
        logger.warning(f"Test skipped for valid cache mode enum value: '{c_uint32_randomize}'. ")


@pytest.mark.security
@pytest.mark.parametrize("cm", CacheMode)
def test_fuzzy_start_cache_line_size(pyocf_ctx, c_uint64_randomize, cm):
    """
    Test whether it is impossible to start cache with invalid cache line size value.
    :param pyocf_ctx: basic pyocf context fixture
    :param c_uint64_randomize: cache line size enum value to start cache with
    :param cm: cache mode value to start cache with
    """
    if c_uint64_randomize not in [item.value for item in CacheLineSize]:
        with pytest.raises(OcfError, match="OCF_ERR_INVALID_CACHE_LINE_SIZE"):
            try_start_cache(cache_mode=cm, cache_line_size=c_uint64_randomize)
    else:
        logger.warning(
            f"Test skipped for valid cache line size enum value: '{c_uint64_randomize}'. ")


@pytest.mark.security
@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
def test_fuzzy_start_name(pyocf_ctx, string_randomize, cm, cls):
    """
    Test whether it is possible to start cache with various cache name value.
    :param pyocf_ctx: basic pyocf context fixture
    :param string_randomize: fuzzed cache name value to start cache with
    :param cm: cache mode value to start cache with
    :param cls: cache line size value to start cache with
    """
    cache_device = Volume(Size.from_MiB(30))
    try:
        cache = Cache.start_on_device(cache_device, name=string_randomize, cache_mode=cm,
                                      cache_line_size=cls)
    except OcfError:
        logger.error(f"Cache did not start properly with correct name value: {string_randomize}")
    cache.stop()


@pytest.mark.security
@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
def test_fuzzy_start_id(pyocf_ctx, c_uint16_randomize, cm, cls):
    """
    Test whether it is impossible to start cache with invalid cache id value.
    :param pyocf_ctx: basic pyocf context fixture
    :param c_uint16_randomize: cache id value to start cache with
    :param cm: cache mode value to start cache with
    :param cls: cache line size value to start cache with
    """
    max_id_val = 1 << 14
    if c_uint16_randomize > max_id_val:
        with pytest.raises(OcfError, match="OCF_ERR_INVAL"):
            try_start_cache(cache_id=c_uint16_randomize, cache_mode=cm, cache_line_size=cls)
    else:
        logger.warning(f"Test skipped for valid cache id value: '{c_uint16_randomize}'. ")


@pytest.mark.security
@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
def test_fuzzy_start_eviction_policy(pyocf_ctx, c_uint32_randomize, cm, cls):
    """
    Test whether it is impossible to start cache with invalid eviction policy value.
    :param pyocf_ctx: basic pyocf context fixture
    :param c_uint32_randomize: eviction policy enum value to start cache with
    :param cm: cache mode value to start cache with
    :param cls: cache line size value to start cache with
    """
    if c_uint32_randomize not in [item.value for item in EvictionPolicy]:
        with pytest.raises(OcfError, match="OCF_ERR_INVAL"):
            try_start_cache(eviction_policy=c_uint32_randomize, cache_mode=cm, cache_line_size=cls)
    else:
        logger.warning(
            f"Test skipped for valid eviction policy enum value: '{c_uint32_randomize}'. ")


@pytest.mark.security
@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
def test_fuzzy_start_metadata_layout(pyocf_ctx, c_uint32_randomize, cm, cls):
    """
    Test whether it is impossible to start cache with invalid metadata layout value.
    :param pyocf_ctx: basic pyocf context fixture
    :param c_uint32_randomize: metadata layout enum value to start cache with
    :param cm: cache mode value to start cache with
    :param cls: cache line size value to start cache with
    """
    if c_uint32_randomize not in [item.value for item in MetadataLayout]:
        with pytest.raises(OcfError, match="OCF_ERR_INVAL"):
            try_start_cache(metadata_layout=c_uint32_randomize, cache_mode=cm, cache_line_size=cls)
    else:
        logger.warning(
            f"Test skipped for valid metadata layout enum value: '{c_uint32_randomize}'. ")


@pytest.mark.security
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.parametrize('max_wb_queue_size', generate_random_numbers(c_uint32, 10))
def test_fuzzy_start_max_queue_size(pyocf_ctx, max_wb_queue_size, c_uint32_randomize, cls):
    """
    Test whether it is impossible to start cache with invalid dependence between max queue size
    and queue unblock size.
    :param pyocf_ctx: basic pyocf context fixture
    :param max_wb_queue_size: max queue size value to start cache with
    :param c_uint32_randomize: queue unblock size value to start cache with
    :param cls: cache line size value to start cache with
    """
    if c_uint32_randomize >= max_wb_queue_size:
        with pytest.raises(OcfError, match="OCF_ERR_INVAL"):
            try_start_cache(
                max_queue_size=max_wb_queue_size,
                queue_unblock_size=c_uint32_randomize,
                cache_mode=CacheMode.WB,
                cache_line_size=cls)
    else:
        logger.warning(f"Test skipped for valid values: "
                       f"'max_queue_size={max_wb_queue_size}, "
                       f"queue_unblock_size={c_uint32_randomize}'.")
