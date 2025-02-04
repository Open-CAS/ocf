#
# Copyright(c) 2019-2022 Intel Corporation
# Copyright(c) 2024 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import (
    c_void_p,
    c_int,
    c_uint32,
    c_uint64,
    CFUNCTYPE,
    Structure,
    POINTER,
    byref,
    cast,
)
from enum import IntEnum

from ..ocf import OcfLib
from .data import Data
from .shared import OcfCompletion


class WriteMode(IntEnum):
    ZERO_PAD = 0
    READ_MODIFY_WRITE = 1


class IoDir(IntEnum):
    READ = 0
    WRITE = 1


class IoOps(Structure):
    pass


class Io(Structure):
    START = CFUNCTYPE(None, c_void_p)
    HANDLE = CFUNCTYPE(None, c_void_p, c_void_p)
    END = CFUNCTYPE(None, c_void_p, c_void_p, c_void_p, c_int)

    _instances_ = {}
    _fields_ = [
        ("_addr", c_uint64),
        ("_flags", c_uint64),
        ("_bytes", c_uint32),
        ("_class", c_uint32),
        ("_dir", c_uint32),
        ("_io_queue", c_void_p),
        ("_start", START),
        ("_priv1", c_void_p),
        ("_priv2", c_void_p),
        ("_handle", HANDLE),
        ("_end", END),
    ]

    @classmethod
    def from_pointer(cls, ref):
        c = cls.from_address(ref)
        cls._instances_[ref] = c
        OcfLib.getInstance().ocf_io_set_cmpl_wrapper(byref(c), None, None, c.c_end)
        return c

    @classmethod
    def get_instance(cls, ref):
        return cls._instances_[cast(ref, c_void_p).value]

    @staticmethod
    def forward_get(token):
        OcfLib.getInstance().ocf_forward_get(token)

    @staticmethod
    def forward_end(token, error):
        OcfLib.getInstance().ocf_forward_end(token, error)

    def del_object(self):
        del type(self)._instances_[cast(byref(self), c_void_p).value]

    def put(self):
        OcfLib.getInstance().ocf_io_put(byref(self))

    @staticmethod
    @END
    def c_end(io, priv1, priv2, err):
        Io.get_instance(io).end(priv1, priv2, err)

    @staticmethod
    @START
    def c_start(io):
        Io.get_instance(io).start()

    @staticmethod
    @HANDLE
    def c_handle(io, opaque):
        Io.get_instance(io).handle(opaque)

    def end(self, priv1, priv2, err):
        try:
            self.callback(err)
        except:  # noqa E722
            pass

        self.del_object()
        self.put()

    def submit(self):
        return OcfLib.getInstance().ocf_volume_submit_io(byref(self))

    def submit_flush(self):
        return OcfLib.getInstance().ocf_volume_submit_flush(byref(self))

    def submit_discard(self):
        return OcfLib.getInstance().ocf_volume_submit_discard(byref(self))

    def submit_flush(self):
        return OcfLib.getInstance().ocf_volume_submit_flush(byref(self))

    def submit_discard(self):
        return OcfLib.getInstance().ocf_volume_submit_discard(byref(self))

    def set_data(self, data: Data, offset: int = 0):
        self.data = data
        OcfLib.getInstance().ocf_io_set_data(byref(self), data, offset)


class Sync:
    def __init__(self, io: Io) -> None:
        self.io = io

    def sync_submit(self, submit_method):
        if getattr(self.io, "callback", None):
            raise Exception("completion callback is already set")
        cmpl = OcfCompletion([("err", c_int)])
        self.io.callback = cmpl.callback
        submit_method()
        cmpl.wait()
        return cmpl

    def submit(self):
        return self.sync_submit(self.io.submit)

    def submit_flush(self):
        return self.sync_submit(self.io.submit_flush)

    def submit_discard(self):
        return self.sync_submit(self.io.submit_discard)


IoOps.SET_DATA = CFUNCTYPE(c_int, POINTER(Io), c_void_p, c_uint32)
IoOps.GET_DATA = CFUNCTYPE(c_void_p, POINTER(Io))

IoOps._fields_ = [("_set_data", IoOps.SET_DATA), ("_get_data", IoOps.GET_DATA)]

lib = OcfLib.getInstance()

lib.ocf_forward_get.argtypes = [c_uint64]

lib.ocf_forward_end.argtypes = [c_uint64, c_int]

lib.ocf_io_set_cmpl_wrapper.argtypes = [POINTER(Io), c_void_p, c_void_p, Io.END]

lib.ocf_io_set_data.argtypes = [POINTER(Io), c_void_p, c_uint32]
lib.ocf_io_set_data.restype = c_int

lib.ocf_volume_submit_io.argtypes = [POINTER(Io)]
lib.ocf_volume_submit_io.restype = None

lib.ocf_volume_submit_flush.argtypes = [POINTER(Io)]
lib.ocf_volume_submit_flush.restype = None

lib.ocf_volume_submit_discard.argtypes = [POINTER(Io)]
lib.ocf_volume_submit_discard.restype = None
