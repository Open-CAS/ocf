#
# Copyright(c) 2022 Intel Corporation
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import (
    c_uint8,
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
from .shared import OcfError, Uuid, OcfErrorCode
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

    def detach_member(self, member_id):
        ret = lib.ocf_composite_volume_detach_member(self.cvol, member_id)

        ret = abs(ret)

        if ret == 0:
            return

        elif ret == OcfErrorCode.OCF_ERR_COMPOSITE_INVALID_ID:
            raise OcfError(
                    "Detaching member from composite failed. Invalid ID.",
                    ret,
                    )

        elif ret == OcfErrorCode.OCF_ERR_COMPOSITE_UNINITIALISED_VOLUME:
            raise OcfError(
                    "Detaching member from composite failed. Uninitialised member.",
                    ret,
                    )

        elif ret == OcfErrorCode.OCF_ERR_COMPOSITE_DETACHED:
            raise OcfError(
                    "Detaching member from composite failed. Member already detached",
                    ret,
                    )

        else:
            raise OcfError(
                    "Detaching member from composite failed",
                    ret,
                    )

        return ret

    def attach_member(self, vol, target_id):
        uuid = Uuid(
            _data=cast(create_string_buffer(vol.uuid.encode("ascii")), c_char_p),
            _size=len(vol.uuid) + 1,
        )

        ocf_vol_type = self.ctx.ocf_volume_type[type(vol)]
        ret = lib.ocf_composite_volume_attach_member(
                self.cvol,
                byref(uuid),
                target_id,
                ocf_vol_type,
                c_void_p(),
                )

        ret = abs(ret)
        if ret == 0:
            return
        elif ret == OcfErrorCode.OCF_ERR_COMPOSITE_INVALID_ID:
            raise OcfError(
                    "Attaching member to composite failed. Invalid ID.",
                    ret,
                    )

        elif ret == OcfErrorCode.OCF_ERR_COMPOSITE_UNINITIALISED_VOLUME:
            raise OcfError(
                    "Attaching member to composite failed. Uninitialised member.",
                    ret,
                    )

        elif ret == OcfErrorCode.OCF_ERR_COMPOSITE_ATTACHED:
            raise OcfError(
                    "Attaching member to composite failed. Member already attached",
                    ret,
                    )

        elif ret == OcfErrorCode.OCF_ERR_COMPOSITE_INVALID_SIZE:
            raise OcfError(
                    "Attaching member to composite failed. Invalid size.",
                    ret
                    )

        else:
            raise OcfError(
                    "Attaching member to composite failed",
                    ret,
                    )

    def get_c_handle(self):
        return self.cvol.value

    def open(self):
        ret = super().open()
        if ret == 0:
            ret = self.lib.ocf_volume_open(self.handle, c_void_p())

        if ret:
            raise OcfError("opening composite volume failed", ret)

        return ret

    def close(self):
        self.lib.ocf_volume_close(self.handle)
        super().close()



lib = OcfLib.getInstance()
lib.ocf_composite_volume_create.restype = c_int
lib.ocf_composite_volume_create.argtypes = [c_void_p, c_void_p]
lib.ocf_composite_volume_destroy.argtypes = [c_void_p]
lib.ocf_composite_volume_add.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
lib.ocf_composite_volume_add.restype = c_int
lib.ocf_composite_volume_detach_member.argtypes = [c_void_p, c_int]
lib.ocf_composite_volume_detach_member.restype = c_int
lib.ocf_composite_volume_attach_member.argtypes = [c_void_p, c_void_p, c_uint8, c_void_p, c_void_p]
lib.ocf_composite_volume_attach_member.restype = c_int
lib.ocf_volume_open.restype = c_int
lib.ocf_volume_open.argtypes = [c_void_p, c_void_p]
lib.ocf_volume_close.argtypes = [c_void_p]
