#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import (
    c_uint64,
    c_uint32,
    c_uint16,
    c_int,
    c_char,
    c_char_p,
    c_void_p,
    c_bool,
    c_uint8,
    Structure,
    byref,
    cast,
    create_string_buffer,
)
from enum import IntEnum
from datetime import timedelta

from ..ocf import OcfLib
from .shared import (
    Uuid,
    OcfError,
    CacheLineSize,
    CacheLines,
    OcfCompletion,
    SeqCutOffPolicy,
)
from ..utils import Size, struct_to_dict
from .core import Core
from .queue import Queue
from .stats.cache import CacheInfo
from .stats.shared import UsageStats, RequestsStats, BlocksStats, ErrorsStats


class Backfill(Structure):
    _fields_ = [("_max_queue_size", c_uint32), ("_queue_unblock_size", c_uint32)]


class CacheConfig(Structure):
    MAX_CACHE_NAME_SIZE = 32
    _fields_ = [
        ("_name", c_char * MAX_CACHE_NAME_SIZE),
        ("_cache_mode", c_uint32),
        ("_eviction_policy", c_uint32),
        ("_promotion_policy", c_uint32),
        ("_cache_line_size", c_uint64),
        ("_metadata_layout", c_uint32),
        ("_metadata_volatile", c_bool),
        ("_backfill", Backfill),
        ("_locked", c_bool),
        ("_pt_unaligned_io", c_bool),
        ("_use_submit_io_fast", c_bool),
    ]


class CacheDeviceConfig(Structure):
    _fields_ = [
        ("_uuid", Uuid),
        ("_volume_type", c_uint8),
        ("_cache_line_size", c_uint64),
        ("_force", c_bool),
        ("_min_free_ram", c_uint64),
        ("_perform_test", c_bool),
        ("_discard_on_start", c_bool),
    ]


class ConfValidValues:
    promotion_nhit_insertion_threshold_range = range(2, 1000)
    promotion_nhit_trigger_threshold_range = range(0, 100)


class CacheMode(IntEnum):
    WT = 0
    WB = 1
    WA = 2
    PT = 3
    WI = 4
    WO = 5
    DEFAULT = WT

    def lazy_write(self):
        return self.value in [CacheMode.WB, CacheMode.WO]

    def write_insert(self):
        return self.value not in [CacheMode.PT, CacheMode.WA, CacheMode.WI]

    def read_insert(self):
        return self.value not in [CacheMode.PT, CacheMode.WO]


class EvictionPolicy(IntEnum):
    LRU = 0
    DEFAULT = LRU


class PromotionPolicy(IntEnum):
    ALWAYS = 0
    NHIT = 1
    DEFAULT = ALWAYS


class NhitParams(IntEnum):
    INSERTION_THRESHOLD = 0
    TRIGGER_THRESHOLD = 1


class CleaningPolicy(IntEnum):
    NOP = 0
    ALRU = 1
    ACP = 2
    DEFAULT = ALRU


class AlruParams(IntEnum):
    WAKE_UP_TIME = 0
    STALE_BUFFER_TIME = 1
    FLUSH_MAX_BUFFERS = 2
    ACTIVITY_THRESHOLD = 3


class AcpParams(IntEnum):
    WAKE_UP_TIME = 0
    FLUSH_MAX_BUFFERS = 1


class MetadataLayout(IntEnum):
    STRIPING = 0
    SEQUENTIAL = 1
    DEFAULT = STRIPING


class Cache:
    DEFAULT_BACKFILL_QUEUE_SIZE = 65536
    DEFAULT_BACKFILL_UNBLOCK = 60000
    DEFAULT_PT_UNALIGNED_IO = False
    DEFAULT_USE_SUBMIT_FAST = False

    def __init__(
        self,
        owner,
        name: str = "cache",
        cache_mode: CacheMode = CacheMode.DEFAULT,
        eviction_policy: EvictionPolicy = EvictionPolicy.DEFAULT,
        promotion_policy: PromotionPolicy = PromotionPolicy.DEFAULT,
        cache_line_size: CacheLineSize = CacheLineSize.DEFAULT,
        metadata_layout: MetadataLayout = MetadataLayout.DEFAULT,
        metadata_volatile: bool = False,
        max_queue_size: int = DEFAULT_BACKFILL_QUEUE_SIZE,
        queue_unblock_size: int = DEFAULT_BACKFILL_UNBLOCK,
        locked: bool = False,
        pt_unaligned_io: bool = DEFAULT_PT_UNALIGNED_IO,
        use_submit_fast: bool = DEFAULT_USE_SUBMIT_FAST,
    ):
        self.device = None
        self.started = False
        self.owner = owner
        self.cache_line_size = cache_line_size

        self.cfg = CacheConfig(
            _name=name.encode("ascii"),
            _cache_mode=cache_mode,
            _eviction_policy=eviction_policy,
            _promotion_policy=promotion_policy,
            _cache_line_size=cache_line_size,
            _metadata_layout=metadata_layout,
            _metadata_volatile=metadata_volatile,
            _backfill=Backfill(
                _max_queue_size=max_queue_size, _queue_unblock_size=queue_unblock_size
            ),
            _locked=locked,
            _pt_unaligned_io=pt_unaligned_io,
            _use_submit_fast=use_submit_fast,
        )
        self.cache_handle = c_void_p()
        self._as_parameter_ = self.cache_handle
        self.io_queues = []
        self.cores = []

    def start_cache(self, default_io_queue: Queue = None, mngt_queue: Queue = None):
        status = self.owner.lib.ocf_mngt_cache_start(
            self.owner.ctx_handle, byref(self.cache_handle), byref(self.cfg)
        )
        if status:
            raise OcfError("Creating cache instance failed", status)
        self.owner.caches.append(self)

        self.mngt_queue = mngt_queue or Queue(self, "mgmt-{}".format(self.get_name()))

        if default_io_queue:
            self.io_queues += [default_io_queue]
        else:
            self.io_queues += [Queue(self, "default-io-{}".format(self.get_name()))]

        status = self.owner.lib.ocf_mngt_cache_set_mngt_queue(self, self.mngt_queue)
        if status:
            raise OcfError("Error setting management queue", status)

        self.started = True

    def change_cache_mode(self, cache_mode: CacheMode):
        self.write_lock()
        status = self.owner.lib.ocf_mngt_cache_set_mode(self.cache_handle, cache_mode)

        self.write_unlock()

        if status:
            raise OcfError("Error changing cache mode", status)

    def set_cleaning_policy(self, cleaning_policy: CleaningPolicy):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_cache_cleaning_set_policy(
            self.cache_handle, cleaning_policy
        )

        self.write_unlock()

        if status:
            raise OcfError("Error changing cleaning policy", status)

    def set_cleaning_policy_param(
        self, cleaning_policy: CleaningPolicy, param_id, param_value
    ):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_cache_cleaning_set_param(
            self.cache_handle, cleaning_policy, param_id, param_value
        )

        self.write_unlock()

        if status:
            raise OcfError("Error setting cleaning policy param", status)

    def set_promotion_policy(self, promotion_policy: PromotionPolicy):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_cache_promotion_set_policy(
            self.cache_handle, promotion_policy
        )

        self.write_unlock()
        if status:
            raise OcfError("Error setting promotion policy", status)

    def get_promotion_policy_param(self, promotion_type, param_id):
        self.read_lock()

        param_value = c_uint64()

        status = self.owner.lib.ocf_mngt_cache_promotion_get_param(
            self.cache_handle, promotion_type, param_id, byref(param_value)
        )

        self.read_unlock()
        if status:
            raise OcfError("Error getting promotion policy parameter", status)

        return param_value

    def set_promotion_policy_param(self, promotion_type, param_id, param_value):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_cache_promotion_set_param(
            self.cache_handle, promotion_type, param_id, param_value
        )

        self.write_unlock()
        if status:
            raise OcfError("Error setting promotion policy parameter", status)

    def set_seq_cut_off_policy(self, policy: SeqCutOffPolicy):
        self.write_lock()

        status = self.owner.lib.ocf_mngt_core_set_seq_cutoff_policy_all(
            self.cache_handle, policy
        )

        self.write_unlock()

        if status:
            raise OcfError("Error setting cache seq cut off policy", status)

    def configure_device(
        self, device, force=False, perform_test=True, cache_line_size=None
    ):
        self.device = device
        self.device_name = device.uuid
        self.dev_cfg = CacheDeviceConfig(
            _uuid=Uuid(
                _data=cast(
                    create_string_buffer(self.device_name.encode("ascii")), c_char_p
                ),
                _size=len(self.device_name) + 1,
            ),
            _volume_type=device.type_id,
            _cache_line_size=cache_line_size
            if cache_line_size
            else self.cache_line_size,
            _force=force,
            _min_free_ram=0,
            _perform_test=perform_test,
            _discard_on_start=False,
        )

    def attach_device(
        self, device, force=False, perform_test=False, cache_line_size=None
    ):
        self.configure_device(device, force, perform_test, cache_line_size)
        self.write_lock()

        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])

        device.owner.lib.ocf_mngt_cache_attach(
            self.cache_handle, byref(self.dev_cfg), c, None
        )

        c.wait()
        self.write_unlock()

        if c.results["error"]:
            raise OcfError("Attaching cache device failed", c.results["error"])

    def load_cache(self, device):
        self.configure_device(device)
        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        device.owner.lib.ocf_mngt_cache_load(
            self.cache_handle, byref(self.dev_cfg), c, None
        )

        c.wait()
        if c.results["error"]:
            raise OcfError("Loading cache device failed", c.results["error"])

    @classmethod
    def load_from_device(cls, device, name="cache"):
        c = cls(name=name, owner=device.owner)

        c.start_cache()
        try:
            c.load_cache(device)
        except:  # noqa E722
            c.stop()
            raise

        return c

    @classmethod
    def start_on_device(cls, device, **kwargs):
        c = cls(owner=device.owner, **kwargs)

        c.start_cache()
        try:
            c.attach_device(device, force=True)
        except:  # noqa E722
            c.stop()
            raise

        return c

    def put(self):
        self.owner.lib.ocf_mngt_cache_put(self.cache_handle)

    def get(self):
        status = self.owner.lib.ocf_mngt_cache_get(self.cache_handle)
        if status:
            raise OcfError("Couldn't get cache instance", status)

    def read_lock(self):
        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_read_lock(self.cache_handle, c, None)
        c.wait()
        if c.results["error"]:
            raise OcfError("Couldn't lock cache instance", c.results["error"])

    def write_lock(self):
        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_lock(self.cache_handle, c, None)
        c.wait()
        if c.results["error"]:
            raise OcfError("Couldn't lock cache instance", c.results["error"])

    def read_unlock(self):
        self.owner.lib.ocf_mngt_cache_read_unlock(self.cache_handle)

    def write_unlock(self):
        self.owner.lib.ocf_mngt_cache_unlock(self.cache_handle)

    def add_core(self, core: Core):
        self.write_lock()

        c = OcfCompletion(
            [
                ("cache", c_void_p),
                ("core", c_void_p),
                ("priv", c_void_p),
                ("error", c_int),
            ]
        )

        self.owner.lib.ocf_mngt_cache_add_core(
            self.cache_handle, byref(core.get_cfg()), c, None
        )

        c.wait()
        if c.results["error"]:
            self.write_unlock()
            raise OcfError("Failed adding core", c.results["error"])

        core.cache = self
        core.handle = c.results["core"]
        self.cores.append(core)

        self.write_unlock()

    def remove_core(self, core: Core):
        self.write_lock()

        c = OcfCompletion([("priv", c_void_p), ("error", c_int)])

        self.owner.lib.ocf_mngt_cache_remove_core(core.handle, c, None)

        c.wait()
        self.write_unlock()

        if c.results["error"]:
            raise OcfError("Failed removing core", c.results["error"])

        self.cores.remove(core)

    def get_stats(self):
        cache_info = CacheInfo()
        usage = UsageStats()
        req = RequestsStats()
        block = BlocksStats()
        errors = ErrorsStats()

        self.read_lock()

        status = self.owner.lib.ocf_cache_get_info(self.cache_handle, byref(cache_info))
        if status:
            self.read_unlock()
            raise OcfError("Failed getting cache info", status)

        status = self.owner.lib.ocf_stats_collect_cache(
            self.cache_handle, byref(usage), byref(req), byref(block), byref(errors)
        )
        if status:
            self.read_unlock()
            raise OcfError("Failed getting stats", status)

        line_size = CacheLineSize(cache_info.cache_line_size)
        cache_name = self.owner.lib.ocf_cache_get_name(self).decode("ascii")

        self.read_unlock()
        return {
            "conf": {
                "attached": cache_info.attached,
                "volume_type": self.owner.volume_types[cache_info.volume_type],
                "size": CacheLines(cache_info.size, line_size),
                "inactive": {
                    "occupancy": CacheLines(
                        cache_info.inactive.occupancy.value, line_size
                    ),
                    "dirty": CacheLines(cache_info.inactive.dirty.value, line_size),
                    "clean": CacheLines(cache_info.inactive.clean.value, line_size),
                },
                "occupancy": CacheLines(cache_info.occupancy, line_size),
                "dirty": CacheLines(cache_info.dirty, line_size),
                "dirty_initial": CacheLines(cache_info.dirty_initial, line_size),
                "dirty_for": timedelta(seconds=cache_info.dirty_for),
                "cache_mode": CacheMode(cache_info.cache_mode),
                "fallback_pt": {
                    "error_counter": cache_info.fallback_pt.error_counter,
                    "status": cache_info.fallback_pt.status,
                },
                "state": cache_info.state,
                "eviction_policy": EvictionPolicy(cache_info.eviction_policy),
                "cleaning_policy": CleaningPolicy(cache_info.cleaning_policy),
                "promotion_policy": PromotionPolicy(cache_info.promotion_policy),
                "cache_line_size": line_size,
                "flushed": CacheLines(cache_info.flushed, line_size),
                "core_count": cache_info.core_count,
                "metadata_footprint": Size(cache_info.metadata_footprint),
                "metadata_end_offset": Size(cache_info.metadata_end_offset),
                "cache_name": cache_name,
            },
            "block": struct_to_dict(block),
            "req": struct_to_dict(req),
            "usage": struct_to_dict(usage),
            "errors": struct_to_dict(errors),
        }

    def reset_stats(self):
        self.owner.lib.ocf_core_stats_initialize_all(self.cache_handle)

    def get_default_queue(self):
        if not self.io_queues:
            raise Exception("No queues added for cache")

        return self.io_queues[0]

    def save(self):
        if not self.started:
            raise Exception("Not started!")

        self.get_and_write_lock()
        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_save(self.cache_handle, c, None)

        c.wait()
        self.put_and_write_unlock()

        if c.results["error"]:
            raise OcfError("Failed saving cache", c.results["error"])

    def stop(self):
        if not self.started:
            raise Exception("Already stopped!")

        self.write_lock()

        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])

        self.owner.lib.ocf_mngt_cache_stop(self.cache_handle, c, None)

        c.wait()
        if c.results["error"]:
            self.write_unlock()
            raise OcfError("Failed stopping cache", c.results["error"])

        self.mngt_queue.put()
        del self.io_queues[:]
        self.started = False

        self.write_unlock()

        self.owner.caches.remove(self)

    def flush(self):
        self.write_lock()

        c = OcfCompletion([("cache", c_void_p), ("priv", c_void_p), ("error", c_int)])
        self.owner.lib.ocf_mngt_cache_flush(self.cache_handle, c, None)
        c.wait()
        self.write_unlock()

        if c.results["error"]:
            raise OcfError("Couldn't flush cache", c.results["error"])

    def get_name(self):
        self.read_lock()

        try:
            return str(self.owner.lib.ocf_cache_get_name(self), encoding="ascii")
        except:  # noqa E722
            raise OcfError("Couldn't get cache name")
        finally:
            self.read_unlock()


lib = OcfLib.getInstance()
lib.ocf_mngt_cache_remove_core.argtypes = [c_void_p, c_void_p, c_void_p]
lib.ocf_mngt_cache_add_core.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
lib.ocf_cache_get_name.argtypes = [c_void_p]
lib.ocf_cache_get_name.restype = c_char_p
lib.ocf_mngt_cache_cleaning_set_policy.argtypes = [c_void_p, c_uint32]
lib.ocf_mngt_cache_cleaning_set_policy.restype = c_int
lib.ocf_mngt_core_set_seq_cutoff_policy_all.argtypes = [c_void_p, c_uint32]
lib.ocf_mngt_core_set_seq_cutoff_policy_all.restype = c_int
lib.ocf_stats_collect_cache.argtypes = [
    c_void_p,
    c_void_p,
    c_void_p,
    c_void_p,
    c_void_p,
]
lib.ocf_stats_collect_cache.restype = c_int
lib.ocf_cache_get_info.argtypes = [c_void_p, c_void_p]
lib.ocf_cache_get_info.restype = c_int
lib.ocf_mngt_cache_cleaning_set_param.argtypes = [
    c_void_p,
    c_uint32,
    c_uint32,
    c_uint32,
]
lib.ocf_mngt_cache_cleaning_set_param.restype = c_int
