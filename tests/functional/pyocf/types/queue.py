#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import c_void_p, CFUNCTYPE, Structure, byref
from threading import Thread, Condition, Lock

from ..ocf import OcfLib
from .shared import OcfError


class QueueOps(Structure):
    KICK = CFUNCTYPE(None, c_void_p)
    KICK_SYNC = CFUNCTYPE(None, c_void_p)
    KICK = CFUNCTYPE(None, c_void_p)
    STOP = CFUNCTYPE(None, c_void_p)

    _fields_ = [("kick", KICK), ("kick_sync", KICK_SYNC), ("stop", STOP)]


class Queue:
    pass


class Queue:
    _instances_ = {}

    @staticmethod
    def io_queue_run(*, queue: Queue, kick: Condition):
        def wait_predicate():
            return queue.stop or OcfLib.getInstance().ocf_queue_pending_io(queue)

        while True:
            with kick:
                kick.wait_for(wait_predicate)

            queue.owner.lib.ocf_queue_run(queue)

            if queue.stop and not queue.owner.lib.ocf_queue_pending_io(queue):
                break

    def __init__(self, cache, name, mngt_queue: bool = False):
        self.owner = cache.owner

        self.ops = QueueOps(kick=type(self)._kick, stop=type(self)._stop)

        self.handle = c_void_p()
        status = self.owner.lib.ocf_queue_create(
            cache.cache_handle, byref(self.handle), byref(self.ops)
        )
        if status:
            raise OcfError("Couldn't create queue object", status)

        Queue._instances_[self.handle.value] = self
        self._as_parameter_ = self.handle

        self.stop_lock = Lock()
        self.stop = False
        self.kick_condition = Condition(self.stop_lock)
        self.thread = Thread(
            group=None,
            target=Queue.io_queue_run,
            name=name,
            kwargs={"queue": self, "kick": self.kick_condition},
            daemon=True,
        )
        self.thread.start()
        self.mngt_queue = mngt_queue

    @classmethod
    def get_instance(cls, ref):
        return cls._instances_[ref]

    @staticmethod
    @QueueOps.KICK_SYNC
    def _kick_sync(ref):
        Queue.get_instance(ref).kick_sync()

    @staticmethod
    @QueueOps.KICK
    def _kick(ref):
        Queue.get_instance(ref).kick()

    @staticmethod
    @QueueOps.STOP
    def _stop(ref):
        Queue.get_instance(ref).stop()

    def kick_sync(self):
        self.owner.lib.ocf_queue_run(self.handle)

    def kick(self):
        with self.kick_condition:
            self.kick_condition.notify_all()

    def stop(self):
        with self.kick_condition:
            self.stop = True
            self.kick_condition.notify_all()

        self.thread.join()
        if self.mngt_queue:
            self.owner.lib.ocf_queue_put(self)
