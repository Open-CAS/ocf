#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import pytest

from pyocf.types.cache import (
    Cache,
    CacheMode,
    CleaningPolicy,
    AlruParams,
    AcpParams,
    PromotionPolicy,
    NhitParams,
    ConfValidValues,
)
from pyocf.types.core import Core
from pyocf.types.volume import Volume
from pyocf.utils import Size as S
from tests.utils.random import RandomGenerator, DefaultRanges
from pyocf.types.shared import OcfError, CacheLineSize, SeqCutOffPolicy
from ctypes import c_uint64, c_uint32, c_uint8


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_change_cache_mode(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to change cache mode to invalid value.
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(cache_device, cache_mode=cm, cache_line_size=cls)

    # Change cache mode to invalid one and check if failed
    for i in RandomGenerator(DefaultRanges.UINT32):
        if i in [item.value for item in CacheMode]:
            continue
        with pytest.raises(OcfError, match="Error changing cache mode"):
            cache.change_cache_mode(i)


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_set_cleaning_policy(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to change cleaning policy to invalid value
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    :return:
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(cache_device, cache_mode=cm, cache_line_size=cls)

    # Set cleaning policy to invalid one and check if failed
    for i in RandomGenerator(DefaultRanges.UINT32):
        if i in [item.value for item in CleaningPolicy]:
            continue
        with pytest.raises(OcfError, match="Error changing cleaning policy"):
            cache.set_cleaning_policy(i)


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_attach_cls(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to change cache line size to
    invalid value while attaching cache device
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    :return:
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache(owner=cache_device.owner, cache_mode=cm, cache_line_size=cls)
    cache.start_cache()

    # Check whether it is possible to attach cache device with invalid cache line size
    for i in RandomGenerator(DefaultRanges.UINT64):
        if i in [item.value for item in CacheLineSize]:
            continue
        with pytest.raises(OcfError, match="Attaching cache device failed"):
            cache.attach_device(cache_device, cache_line_size=i)


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_cache_set_seq_cut_off_policy(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to change cache seq cut-off policy to invalid value
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    :return:
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(cache_device, cache_mode=cm, cache_line_size=cls)

    # Create 2 core devices
    core_device1 = Volume(S.from_MiB(10))
    core1 = Core.using_device(core_device1, name="core1")
    core_device2 = Volume(S.from_MiB(10))
    core2 = Core.using_device(core_device2, name="core2")

    # Add cores
    cache.add_core(core1)
    cache.add_core(core2)

    # Change cache seq cut off policy to invalid one and check if failed
    for i in RandomGenerator(DefaultRanges.UINT32):
        if i in [item.value for item in SeqCutOffPolicy]:
            continue
        with pytest.raises(OcfError, match="Error setting cache seq cut off policy"):
            cache.set_seq_cut_off_policy(i)


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_core_set_seq_cut_off_policy(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to change core seq cut-off policy to invalid value
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    :return:
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(cache_device, cache_mode=cm, cache_line_size=cls)

    # Create core device
    core_device = Volume(S.from_MiB(10))
    core = Core.using_device(core_device)

    # Add core
    cache.add_core(core)

    # Change core seq cut off policy to invalid one and check if failed
    for i in RandomGenerator(DefaultRanges.UINT32):
        if i in [item.value for item in SeqCutOffPolicy]:
            continue
        with pytest.raises(OcfError, match="Error setting core seq cut off policy"):
            core.set_seq_cut_off_policy(i)


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_set_alru_param(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to set invalid param for alru cleaning policy
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    :return:
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(cache_device, cache_mode=cm, cache_line_size=cls)

    # Change invalid alru param and check if failed
    for i in RandomGenerator(DefaultRanges.UINT32):
        if i in [item.value for item in AlruParams]:
            continue
        with pytest.raises(OcfError, match="Error setting cleaning policy param"):
            cache.set_cleaning_policy_param(CleaningPolicy.ALRU, i, 1)


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_set_acp_param(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to set invalid param for acp cleaning policy
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    :return:
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(cache_device, cache_mode=cm, cache_line_size=cls)

    # Change invalid acp param and check if failed
    for i in RandomGenerator(DefaultRanges.UINT32):
        if i in [item.value for item in AcpParams]:
            continue
        with pytest.raises(OcfError, match="Error setting cleaning policy param"):
            cache.set_cleaning_policy_param(CleaningPolicy.ALRU, i, 1)


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_set_promotion_policy(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to set invalid param for promotion policy
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    :return:
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(cache_device, cache_mode=cm, cache_line_size=cls)

    # Change to invalid promotion policy and check if failed
    for i in RandomGenerator(DefaultRanges.UINT32):
        if i in [item.value for item in PromotionPolicy]:
            continue
        with pytest.raises(OcfError, match="Error setting promotion policy"):
            cache.set_promotion_policy(i)


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_set_nhit_promotion_policy_param(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to set invalid promotion policy param id for nhit promotion policy
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    :return:
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(
        cache_device,
        cache_mode=cm,
        cache_line_size=cls,
        promotion_policy=PromotionPolicy.NHIT,
    )

    # Set invalid promotion policy param id and check if failed
    for i in RandomGenerator(DefaultRanges.UINT8):
        if i in [item.value for item in NhitParams]:
            continue
        with pytest.raises(OcfError, match="Error setting promotion policy parameter"):
            cache.set_promotion_policy_param(PromotionPolicy.NHIT, i, 1)


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_set_nhit_promotion_policy_param_trigger(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to set invalid promotion policy param TRIGGER_THRESHOLD for
    nhit promotion policy
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    :return:
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(
        cache_device,
        cache_mode=cm,
        cache_line_size=cls,
        promotion_policy=PromotionPolicy.NHIT,
    )

    # Set to invalid promotion policy trigger threshold and check if failed
    for i in RandomGenerator(DefaultRanges.UINT32):
        if i in ConfValidValues.promotion_nhit_trigger_threshold_range:
            continue
        with pytest.raises(OcfError, match="Error setting promotion policy parameter"):
            cache.set_promotion_policy_param(
                PromotionPolicy.NHIT, NhitParams.TRIGGER_THRESHOLD, i
            )


@pytest.mark.parametrize("cm", CacheMode)
@pytest.mark.parametrize("cls", CacheLineSize)
@pytest.mark.security
def test_neg_set_nhit_promotion_policy_param_threshold(pyocf_ctx, cm, cls):
    """
    Test whether it is possible to set invalid promotion policy param INSERTION_THRESHOLD for
    nhit promotion policy
    :param pyocf_ctx: basic pyocf context fixture
    :param cm: cache mode we start with
    :param cls: cache line size we start with
    :return:
    """
    # Start cache device
    cache_device = Volume(S.from_MiB(30))
    cache = Cache.start_on_device(
        cache_device,
        cache_mode=cm,
        cache_line_size=cls,
        promotion_policy=PromotionPolicy.NHIT,
    )

    # Set to invalid promotion policy insertion threshold and check if failed
    for i in RandomGenerator(DefaultRanges.UINT32):
        if i in ConfValidValues.promotion_nhit_insertion_threshold_range:
            continue
        with pytest.raises(OcfError, match="Error setting promotion policy parameter"):
            cache.set_promotion_policy_param(
                PromotionPolicy.NHIT, NhitParams.INSERTION_THRESHOLD, i
            )
