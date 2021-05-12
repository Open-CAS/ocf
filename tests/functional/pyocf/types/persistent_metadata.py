#
# Copyright(c) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import c_void_p, Structure, c_int, c_size_t, c_bool, POINTER, CFUNCTYPE

class PersistentMetaOps(Structure):
    INIT = CFUNCTYPE(c_void_p, c_void_p, c_size_t, POINTER(c_bool))
    DEINIT = CFUNCTYPE(c_int, c_void_p)
    ALLOC = CFUNCTYPE(c_void_p, c_void_p, c_size_t, c_int, POINTER(c_bool))
    FREE = CFUNCTYPE(c_int, c_void_p, c_int, c_void_p)
    _fields_ = [
        ("_init", INIT),
        ("_deinit", DEINIT),
        ("_alloc", ALLOC),
        ("_free", FREE),
    ]
