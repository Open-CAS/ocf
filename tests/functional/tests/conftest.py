#
# Copyright(c) 2019-2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import os
import sys
import pytest
import gc

sys.path.append(os.path.join(os.path.dirname(__file__), os.path.pardir))
from pyocf.types.logger import LogLevel, DefaultLogger, BufferLogger
from pyocf.types.volume import RamVolume, ErrorDevice
from pyocf.types.volume_cache import CacheVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.types.volume_replicated import ReplicatedVolume
from pyocf.types.cvolume import CVolume
from pyocf.types.ctx import OcfCtx
from pyocf.helpers import get_composite_volume_type_id
from pyocf.types.volume import Volume
import warnings

default_registered_volumes = [RamVolume, ErrorDevice, CacheVolume, CoreVolume, ReplicatedVolume]


def pytest_configure(config):
    sys.path.append(os.path.join(os.path.dirname(__file__), os.path.pardir))


@pytest.fixture()
def pyocf_ctx():
    c = OcfCtx.with_defaults(DefaultLogger(LogLevel.WARN))
    for vol_type in default_registered_volumes:
        c.register_volume_type(vol_type)
    c.register_internal_volume_type_id(CVolume, get_composite_volume_type_id())
    yield c
    c.exit()
    gc.collect()
    if len(Volume._instances_) > 0:
        warnings.warn("Not all Volumes have been closed!!!")


@pytest.fixture()
def pyocf_ctx_log_buffer():
    logger = BufferLogger(LogLevel.DEBUG)
    c = OcfCtx.with_defaults(logger)
    for vol_type in default_registered_volumes:
        c.register_volume_type(vol_type)
    c.register_internal_volume_type_id(CVolume, get_composite_volume_type_id())
    yield logger
    c.exit()
    gc.collect()
    if len(Volume._instances_) > 0:
        warnings.warn("Not all Volumes have been closed!!!")


def pytest_addoption(parser):
    parser.addoption("--debug-log", action="store_true", help="enable debug logs")


@pytest.fixture
def debug_log(request):
    return request.config.getoption("--debug-log")

  
@pytest.fixture()
def pyocf_2_ctx():
    c1 = OcfCtx.with_defaults(DefaultLogger(LogLevel.WARN, "Ctx1"))
    c2 = OcfCtx.with_defaults(DefaultLogger(LogLevel.WARN, "Ctx2"))
    for vol_type in default_registered_volumes:
        c1.register_volume_type(vol_type)
        c2.register_volume_type(vol_type)
    c1.register_internal_volume_type_id(CVolume, get_composite_volume_type_id())
    c2.register_internal_volume_type_id(CVolume, get_composite_volume_type_id())
    yield [c1, c2]
    c1.exit()
    c2.exit()
    gc.collect()
    if len(Volume._instances_) > 0:
        warnings.warn("Not all Volumes have been closed!!!")


@pytest.fixture()
def pyocf_2_ctx_log_buffer():
    logger1 = BufferLogger(LogLevel.WARN, LogLevel.DEBUG, "Ctx1")
    logger2 = BufferLogger(LogLevel.WARN, LogLevel.DEBUG, "Ctx2")
    c1 = OcfCtx.with_defaults(logger1)
    c2 = OcfCtx.with_defaults(logger2)
    for vol_type in default_registered_volumes:
        c1.register_volume_type(vol_type)
        c2.register_volume_type(vol_type)
    yield (c1, logger1, c2, logger2)
    c1.exit()
    c2.exit()
    gc.collect()
    if len(Volume._instances_) > 0:
        warnings.warn("Not all Volumes have been closed!!!")
