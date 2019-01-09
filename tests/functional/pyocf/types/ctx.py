#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import *
from enum import IntEnum

from .logger import LoggerOps, Logger
from .data import DataOps, Data
from .queue import Queue
from .cleaner import CleanerOps, Cleaner
from .metadata_updater import MetadataUpdaterOps, MetadataUpdater
from .shared import OcfError
from ..ocf import OcfLib


class OcfCtxOps(Structure):
    _fields_ = [
        ("data", DataOps),
        ("cleaner", CleanerOps),
        ("metadata_updater", MetadataUpdaterOps),
        ("logger", LoggerOps),
    ]


class OcfCtxCfg(Structure):
    _fields_ = [("name", c_char_p), ("ops", OcfCtxOps), ("logger_priv", c_void_p)]


class OcfCtx:
    def __init__(self, lib, name, logger, data, mu, cleaner):
        self.logger = logger
        self.data = data
        self.mu = mu
        self.cleaner = cleaner
        self.ctx_handle = c_void_p()
        self.lib = lib
        self.volume_types_count = 1
        self.volume_types = {}
        self.caches = []

        self.cfg = OcfCtxCfg(
            name=name,
            ops=OcfCtxOps(
                data=self.data.get_ops(),
                cleaner=self.cleaner.get_ops(),
                metadata_updater=self.mu.get_ops(),
                logger=logger.get_ops(),
            ),
            logger_priv=cast(pointer(logger.get_priv()), c_void_p),
        )

        result = self.lib.ocf_ctx_init(byref(self.ctx_handle), byref(self.cfg))
        if result != 0:
            raise OcfError("Context initialization failed", result)

    def register_volume_type(self, volume_type):
        self.volume_types[self.volume_types_count] = volume_type.get_props()
        volume_type.type_id = self.volume_types_count
        volume_type.owner = self

        result = self.lib.ocf_ctx_register_volume_type(
            self.ctx_handle,
            self.volume_types_count,
            byref(self.volume_types[self.volume_types_count]),
        )
        if result != 0:
            raise OcfError("Data object registration failed", result)

        self.volume_types_count += 1

    def exit(self):
        self.lib.ocf_ctx_exit(self.ctx_handle)


def get_default_ctx(logger):
    return OcfCtx(
        OcfLib.getInstance(),
        b"PyOCF default ctx",
        logger,
        Data,
        MetadataUpdater,
        Cleaner,
    )
