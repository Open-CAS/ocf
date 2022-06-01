#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import (
    c_int,
    c_uint32,
    c_uint64,
    c_void_p,
    c_char_p,
    byref,
    cast,
    create_string_buffer,
)

from ..ocf import OcfLib
from .ctx import OcfCtx
from .io import Io, IoDir
from .queue import Queue
from .shared import OcfError, Uuid
from .volume_exp_obj import OcfInternalVolume


class CVolume(OcfInternalVolume):
    def __init__(self, ctx):
        super().__init__(None)
        self.ctx = ctx
        self.lib = ctx.lib

        self.cvol = c_void_p()
        ret = lib.ocf_composite_volume_create(byref(self.cvol), self.ctx.ctx_handle)

        if ret != 0:
            raise OcfError("Composite volume creation failed", ret)

        self.handle = self.cvol.value

    def destroy(self):
        self.lib.ocf_composite_volume_destroy(self.cvol)
        self.cvol = None
        self.handle = 0

    def add(self, vol):
        uuid = Uuid(
            _data=cast(create_string_buffer(vol.uuid.encode("ascii")), c_char_p),
            _size=len(vol.uuid) + 1,
        )

        volume = c_void_p()
        ocf_vol_type = self.ctx.ocf_volume_type[type(vol)]

        ret = self.lib.ocf_composite_volume_add(self.cvol, ocf_vol_type, byref(uuid), c_void_p())

        if ret != 0:
            raise OcfError("Failed to add volume to a composite volume", ret)

    def get_c_handle(self):
        return self.cvol.value

    def do_open(self):
        ret = self.lib.ocf_volume_open(self.cvol, c_void_p())
        if ret != 0:
            raise OcfError("openning composite volume failed", ret)

    def do_close(self):
        self.lib.ocf_volume_close(self.cvol)


lib = OcfLib.getInstance()
lib.ocf_composite_volume_create.restype = c_int
lib.ocf_composite_volume_create.argtypes = [c_void_p, c_void_p]
lib.ocf_composite_volume_destroy.argtypes = [c_void_p]
lib.ocf_composite_volume_add.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
lib.ocf_composite_volume_add.restype = c_int
lib.ocf_volume_open.restype = c_int
lib.ocf_volume_open.argtypes = [c_void_p, c_void_p]
lib.ocf_volume_close.argtypes = [c_void_p]
