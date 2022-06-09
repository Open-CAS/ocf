#
# Copyright(c) 2019-2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import c_void_p, Structure, c_char_p, cast, pointer, byref, c_int, c_uint8
import weakref

from .logger import LoggerOps, Logger
from .data import DataOps, Data
from .cleaner import CleanerOps, Cleaner
from .shared import OcfError
from ..ocf import OcfLib
from .queue import Queue


class OcfCtxOps(Structure):
    _fields_ = [
        ("data", DataOps),
        ("cleaner", CleanerOps),
        ("logger", LoggerOps),
    ]


class OcfCtxCfg(Structure):
    _fields_ = [("name", c_char_p), ("ops", OcfCtxOps), ("logger_priv", c_void_p)]


class OcfCtx:
    default = None

    def __init__(self, lib, name, logger, data, cleaner):
        self.logger = logger
        self.data = data
        self.cleaner = cleaner
        self.ctx_handle = c_void_p()
        self.lib = lib
        self.volume_types_count = 1
        self.volume_types = {}
        self.ocf_volume_type = {}
        self.caches = []

        self.cfg = OcfCtxCfg(
            name=name,
            ops=OcfCtxOps(
                data=self.data.get_ops(), cleaner=self.cleaner.get_ops(), logger=logger.get_ops(),
            ),
            logger_priv=cast(pointer(logger.get_priv()), c_void_p),
        )

        result = self.lib.ocf_ctx_create(byref(self.ctx_handle), byref(self.cfg))
        if result != 0:
            raise OcfError("Context initialization failed", result)

        if self.default is None or self.default() is None:
            type(self).default = weakref.ref(self)

    @classmethod
    def with_defaults(cls, logger):
        return cls(OcfLib.getInstance(), b"PyOCF default ctx", logger, Data, Cleaner,)

    @classmethod
    def get_default(cls):
        if cls.default is None or cls.default() is None:
            raise Exception("No context instantiated yet")

        return cls.default()

    def register_internal_volume_type_id(self, volume_type, volume_type_id):
        if volume_type_id in self.volume_types:
            raise RuntimeError(f"volume type id {volume_type_id} already used")
        self.volume_types[volume_type_id] = volume_type
        volume_type.internal = True

    def register_volume_type(self, volume_type):
        if self.volume_types_count in self.volume_types:
            raise RuntimeError(
                f"volume type id slot already used by internal volume "
                f"{self.volume_types[self.volume_types_count]}"
            )
        self.volume_types[self.volume_types_count] = volume_type
        volume_type.type_id = self.volume_types_count

        result = self.lib.ocf_ctx_register_volume_type(
            self.ctx_handle,
            self.volume_types_count,
            byref(self.volume_types[self.volume_types_count].get_props()),
        )
        if result != 0:
            raise OcfError("Volume type registration failed", result)

        self.ocf_volume_type[volume_type] = self.lib.ocf_ctx_get_volume_type(
            self.ctx_handle, volume_type.type_id
        )

        volume_type.internal = False

        self.volume_types_count += 1

    def unregister_volume_type(self, vol_type):
        if not vol_type.type_id:
            raise Exception("Already unregistered")

        self.lib.ocf_ctx_unregister_volume_type(self.ctx_handle, vol_type.type_id)

        del self.volume_types[vol_type.type_id]
        del self.ocf_volume_type[vol_type]

    def cleanup_volume_types(self):
        for k, vol_type in list(self.volume_types.items()):
            if vol_type and not vol_type.internal:
                self.unregister_volume_type(vol_type)

    def stop_caches(self):
        for cache in self.caches[:]:
            cache.stop()

    def exit(self):
        self.stop_caches()
        self.cleanup_volume_types()

        self.lib.ocf_ctx_put(self.ctx_handle)
        if type(self).default and type(self).default() == self:
            type(self).default = None


lib = OcfLib.getInstance()
lib.ocf_mngt_cache_get_by_name.argtypes = [c_void_p, c_void_p, c_void_p]
lib.ocf_mngt_cache_get_by_name.restype = c_int
lib.ocf_ctx_get_volume_type.argtypes = [c_void_p, c_uint8]
lib.ocf_ctx_get_volume_type.restype = c_void_p
