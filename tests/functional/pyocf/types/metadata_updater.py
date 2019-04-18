#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import c_void_p, c_int, c_uint32, Structure, CFUNCTYPE
from threading import Thread, Event

from ..ocf import OcfLib


class MetadataUpdaterOps(Structure):
    INIT = CFUNCTYPE(c_int, c_void_p)
    KICK = CFUNCTYPE(None, c_void_p)
    STOP = CFUNCTYPE(None, c_void_p)

    _fields_ = [("_init", INIT), ("_kick", KICK), ("_stop", STOP)]


class MetadataUpdater:
    pass


def mu_run(*, mu: MetadataUpdater, kick: Event, stop: Event):
    while True:
        kick.clear()

        if OcfLib.getInstance().ocf_metadata_updater_run(mu):
            continue

        kick.wait()
        if stop.is_set():
            break


class MetadataUpdater:
    _instances_ = {}
    ops = None

    def __init__(self, ref):
        self._as_parameter_ = ref
        MetadataUpdater._instances_[ref] = self
        self.kick_event = Event()
        self.stop_event = Event()

        lib = OcfLib.getInstance()
        self.thread = Thread(
            group=None,
            target=mu_run,
            name="mu-{}".format(
                lib.ocf_cache_get_name(lib.ocf_metadata_updater_get_cache(self))
            ),
            kwargs={"mu": self, "kick": self.kick_event, "stop": self.stop_event},
        )
        self.thread.start()

    @classmethod
    def get_ops(cls):
        if not cls.ops:
            cls.ops = MetadataUpdaterOps(
                _init=cls._init, _kick=cls._kick, _stop=cls._stop
            )
        return cls.ops

    @classmethod
    def get_instance(cls, ref):
        return cls._instances_[ref]

    @classmethod
    def del_instance(cls, ref):
        del cls._instances_[ref]

    @staticmethod
    @MetadataUpdaterOps.INIT
    def _init(ref):
        m = MetadataUpdater(ref)
        return 0

    @staticmethod
    @MetadataUpdaterOps.KICK
    def _kick(ref):
        MetadataUpdater.get_instance(ref).kick()

    @staticmethod
    @MetadataUpdaterOps.STOP
    def _stop(ref):
        MetadataUpdater.get_instance(ref).stop()
        del MetadataUpdater._instances_[ref]

    def kick(self):
        self.kick_event.set()

    def stop(self):
        self.stop_event.set()
        self.kick_event.set()


lib = OcfLib.getInstance()
lib.ocf_metadata_updater_get_cache.argtypes = [c_void_p]
lib.ocf_metadata_updater_get_cache.restype = c_void_p
lib.ocf_metadata_updater_run.argtypes = [c_void_p]
lib.ocf_metadata_updater_run.restype = c_uint32
