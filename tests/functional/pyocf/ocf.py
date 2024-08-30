#
# Copyright(c) 2019-2021 Intel Corporation
# Copyright(c) 2024 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#
from ctypes import c_int, c_void_p, cdll
import inspect
import os


class OcfLib:
    __lib__ = None

    @classmethod
    def getInstance(cls):
        if cls.__lib__ is None:
            lib = cdll.LoadLibrary(
                os.path.join(os.path.dirname(inspect.getfile(inspect.currentframe())), "libocf.so",)
            )
            lib.ocf_volume_get_uuid.restype = c_void_p
            lib.ocf_volume_get_uuid.argtypes = [c_void_p]

            lib.ocf_core_get_front_volume.restype = c_void_p
            lib.ocf_core_get_front_volume.argtypes = [c_void_p]

            lib.ocf_queue_create_mngt.restype = c_int
            lib.ocf_queue_create_mngt.argtypes = [c_void_p, c_void_p, c_void_p]

            cls.__lib__ = lib

        return cls.__lib__
