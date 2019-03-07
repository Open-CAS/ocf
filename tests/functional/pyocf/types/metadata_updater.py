#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import *
from .shared import SharedOcfObject


class MetadataUpdaterOps(Structure):
    INIT = CFUNCTYPE(c_int, c_void_p)
    KICK = CFUNCTYPE(None, c_void_p)
    STOP = CFUNCTYPE(None, c_void_p)

    _fields_ = [("_init", INIT), ("_kick", KICK), ("_stop", STOP)]


class MetadataUpdater(SharedOcfObject):
    _instances_ = {}
    _fields_ = [("mu", c_void_p)]
    ops = None

    def __init__(self):
        self._as_parameter_ = self.mu
        super().__init__()

    @classmethod
    def get_ops(cls):
        if not cls.ops:
            cls.ops = MetadataUpdaterOps(
                _init=cls._init, _kick=cls._kick, _stop=cls._stop
            )
        return cls.ops

    @staticmethod
    @MetadataUpdaterOps.INIT
    def _init(ref):
        return 0

    @staticmethod
    @MetadataUpdaterOps.KICK
    def _kick(ref):
        pass

    @staticmethod
    @MetadataUpdaterOps.STOP
    def _stop(ref):
        pass
