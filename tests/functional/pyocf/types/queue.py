#
# Copyright(c) 2019-2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import c_void_p, CFUNCTYPE, Structure, byref
from threading import Thread, Condition, Event, Semaphore
import weakref

from ..ocf import OcfLib
from .shared import OcfError


class QueueOps(Structure):
    KICK = CFUNCTYPE(None, c_void_p)
    KICK_SYNC = CFUNCTYPE(None, c_void_p)
    STOP = CFUNCTYPE(None, c_void_p)

    _fields_ = [("kick", KICK), ("kick_sync", KICK_SYNC), ("stop", STOP)]


class Queue:
    pass


def io_queue_run(*, queue: Queue, kick: Condition, stop: Event, sem: Semaphore):
    def wait_predicate():
        return stop.is_set() or OcfLib.getInstance().ocf_queue_pending_io(queue)

    while True:
        with kick:
            kick.wait_for(wait_predicate)

        sem.acquire()
        OcfLib.getInstance().ocf_queue_run(queue)
        sem.release()

        if stop.is_set() and not OcfLib.getInstance().ocf_queue_pending_io(queue):
            break


class Queue:
    _instances_ = weakref.WeakValueDictionary()

    def __init__(self, cache, name):

        self.ops = QueueOps(kick=type(self)._kick, stop=type(self)._stop)
        self.name = name

        self.handle = c_void_p()
        status = OcfLib.getInstance().ocf_queue_create(
            cache.cache_handle, byref(self.handle), byref(self.ops)
        )
        if status:
            raise OcfError("Couldn't create queue object", status)

        Queue._instances_[self.handle.value] = self
        self._as_parameter_ = self.handle

        self.stop_event = Event()
        self.kick_condition = Condition()
        self.sem = Semaphore()
        self.thread = Thread(
            group=None,
            target=io_queue_run,
            name=name,
            kwargs={
                "queue": self,
                "kick": self.kick_condition,
                "stop": self.stop_event,
                "sem": self.sem,
            },
        )
        self.thread.start()

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
        OcfLib.getInstance().ocf_queue_run(self.handle)

    def kick(self):
        with self.kick_condition:
            self.kick_condition.notify_all()

    def put(self):
        OcfLib.getInstance().ocf_queue_put(self)

    def stop(self):
        with self.kick_condition:
            self.stop_event.set()
            self.kick_condition.notify_all()

        self.thread.join()

    # settle - wait for OCF to finish execution within this queue context
    #
    # In some tests simply waiting for I/O to finish is not enough. Most
    # notably some statistics are potentially incremented after user triggered
    # I/O is finished. This is due to asynchronous nature of I/O operations
    # and OCF approach to statistics update, where only eventual consistency
    # is guaranteed without explicit mechanism available to query whether
    # the final state is reached yet. However it is fully within the adapter power
    # to determine this, as OCF executes in context of API calls from the
    # adapter (like I/O submission, ocf_queue_run, ocf_cleaner_run, management
    # operations) and I/O completion callbacks. Queue settle is a mechanism to
    # assure ocf_queue_run is not being executed by the thread associated with
    # a queue.
    #
    # With queue settle mechanism it is straightforward for the client to
    # wait for cache statistics to reach fixed values:
    #  1. wait for all I/O to OCF to finish
    #  2. settle all I/O queues
    #  3. make sure background cleaner is not active
    #
    def settle(self):
        busy = not self.sem.acquire(blocking=False)
        if busy:
            self.sem.acquire()
        self.sem.release()
        return busy

    # wait until all queues provided settle
    @staticmethod
    def settle_many(qlist: [Queue]):
        status = [True]
        while any(status):
            status = [q.settle() for q in qlist]
