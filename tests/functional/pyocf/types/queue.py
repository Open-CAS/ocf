#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import *

from ..ocf import OcfLib
from .shared import SharedOcfObject, OcfError


class QueueOps(Structure):
    KICK = CFUNCTYPE(None, c_void_p)
    KICK_SYNC = CFUNCTYPE(None, c_void_p)
    STOP = CFUNCTYPE(None, c_void_p)

    _fields_ = [
        ("kick", KICK),
        ("kick_sync", KICK_SYNC),
        ("stop", STOP),
    ]


class Queue:
    _instances_ = {}

    def __init__(self, cache):
        self.ops = QueueOps(kick_sync=type(self)._kick_sync, stop=type(self)._stop)
        self.handle = c_void_p()

        status = OcfLib.getInstance().ocf_queue_create(cache.cache_handle, byref(self.handle), byref(self.ops))
        if status:
            raise OcfError("Couldn't create queue object", status)

        Queue._instances_[self.handle.value] = self
        cache.queues += [self]

    @classmethod
    def get_instance(cls, ref):
        return cls._instances_[ref]

    @staticmethod
    @QueueOps.KICK_SYNC
    def _kick_sync(ref):
        Queue.get_instance(ref).kick_sync()

    @staticmethod
    @QueueOps.STOP
    def _stop(ref):
        Queue.get_instance(ref).stop()

    def kick_sync(self):
        OcfLib.getInstance().ocf_queue_run(self.handle)

    def stop(self):
        pass
