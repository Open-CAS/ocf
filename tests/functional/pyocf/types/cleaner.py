#
# Copyright(c) 2019-2021 Intel Corporation
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import c_void_p, c_uint32, c_int, CFUNCTYPE, Structure
from threading import Thread, Timer, Event
from .shared import SharedOcfObject
from ..ocf import OcfLib


class CleanerOps(Structure):
    INIT = CFUNCTYPE(c_int, c_void_p)
    KICK = CFUNCTYPE(None, c_void_p)
    STOP = CFUNCTYPE(None, c_void_p)

    _fields_ = [("init", INIT), ("kick", KICK), ("stop", STOP)]


CLEANER_END = CFUNCTYPE(None, c_void_p, c_uint32)


class _CleanerState:
    def __init__(self):
        self.kick_event = Event()
        self.stop_event = Event()
        self.thread = None
        self.timer = None
        self.queue = None
        self.last_interval = 0


class Cleaner(SharedOcfObject):
    _instances_ = {}
    _fields_ = [("cleaner", c_void_p)]
    _cleaners = {}
    _end_handler = None
    _kick_handler = None

    def __init__(self):
        self._as_parameter_ = self.cleaner
        super().__init__()

    @classmethod
    def get_ops(cls):
        return CleanerOps(init=cls._init, kick=cls._kick, stop=cls._stop)

    @classmethod
    def set_end_handler(cls, handler):
        """Override the default end handler.

        The handler receives (cleaner, interval) and is responsible for
        scheduling the next cleaner iteration.  Set to None to restore
        the default behaviour (wait the interval before re-kicking).
        """
        cls._end_handler = handler

    @classmethod
    def set_kick_handler(cls, handler):
        """Override the default kick handler.

        The handler receives (cleaner) and decides whether to schedule a
        cleaner iteration.  Set to None to restore the default behaviour
        (kick the cleaner thread to run an iteration).
        """
        cls._kick_handler = handler

    @staticmethod
    def _resolve_queue(cleaner):
        from pyocf.types.ctx import OcfCtx

        cache_handle = lib.ocf_cleaner_get_cache(cleaner)

        ctx = OcfCtx.get_default()
        if ctx is None:
            return None

        for c in ctx.caches:
            if c.cache_handle.value == cache_handle and c.io_queues:
                return c.io_queues[0]

        return None

    @staticmethod
    def _cleaner_thread(cleaner):
        state = Cleaner._cleaners.get(cleaner)
        if not state:
            return

        while not state.stop_event.is_set():
            state.kick_event.wait()
            if state.stop_event.is_set():
                break
            state.kick_event.clear()
            if state.queue:
                lib.ocf_cleaner_run(cleaner, state.queue.handle)

    @staticmethod
    def _default_end(cleaner, interval):
        state = Cleaner._cleaners.get(cleaner)
        if state is None or state.stop_event.is_set():
            return
        state.last_interval = interval
        if interval > 0:
            state.timer = Timer(
                interval / 1000.0, state.kick_event.set
            )
            state.timer.daemon = True
            state.timer.start()
        else:
            state.kick_event.set()

    @staticmethod
    @CleanerOps.INIT
    def _init(cleaner):
        lib.ocf_cleaner_set_cmpl(cleaner, Cleaner._end)

        state = _CleanerState()
        state.queue = Cleaner._resolve_queue(cleaner)
        Cleaner._cleaners[cleaner] = state

        state.thread = Thread(
            target=Cleaner._cleaner_thread,
            args=(cleaner,),
            daemon=True,
            name="cleaner",
        )
        state.thread.start()
        return 0

    @staticmethod
    def _default_kick(cleaner):
        state = Cleaner._cleaners.get(cleaner)
        if state is None:
            return
        if state.queue is None:
            state.queue = Cleaner._resolve_queue(cleaner)
        state.kick_event.set()

    @staticmethod
    @CleanerOps.KICK
    def _kick(cleaner):
        handler = Cleaner._kick_handler
        if handler is not None:
            handler(cleaner)
        else:
            Cleaner._default_kick(cleaner)

    @staticmethod
    @CLEANER_END
    def _end(cleaner, interval):
        handler = Cleaner._end_handler
        if handler is not None:
            handler(cleaner, interval)
        else:
            Cleaner._default_end(cleaner, interval)

    @staticmethod
    @CleanerOps.STOP
    def _stop(cleaner):
        state = Cleaner._cleaners.pop(cleaner, None)
        if state is None:
            return
        state.stop_event.set()
        if state.timer:
            state.timer.cancel()
        state.kick_event.set()
        if state.thread and state.thread.is_alive():
            state.thread.join(timeout=5)


lib = OcfLib.getInstance()
lib.ocf_cleaner_set_cmpl.argtypes = [c_void_p, CLEANER_END]
lib.ocf_cleaner_get_cache.argtypes = [c_void_p]
lib.ocf_cleaner_get_cache.restype = c_void_p
lib.ocf_cleaner_run.argtypes = [c_void_p, c_void_p]
lib.ocf_kick_cleaner.argtypes = [c_void_p]
