#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import *
from enum import IntEnum
import logging
from datetime import timedelta

from .shared import Uuid, OcfError, CacheLineSize, CacheLines
from ..utils import Size, struct_to_dict
from .core import Core
from .stats.cache import *
from .stats.shared import *


class Backfill(Structure):
    _fields_ = [("_max_queue_size", c_uint32), ("_queue_unblock_size", c_uint32)]


class CacheConfig(Structure):
    _fields_ = [
        ("_id", c_uint16),
        ("_name", c_char_p),
        ("_cache_mode", c_uint32),
        ("_eviction_policy", c_uint32),
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


class CacheMode(IntEnum):
    WT = 0
    WB = 1
    WA = 2
    PT = 3
    WI = 4
    DEFAULT = WT


class EvictionPolicy(IntEnum):
    LRU = 0
    DEFAULT = LRU


class CleaningPolicy(IntEnum):
    NOP = 0
    ALRU = 1
    ACP = 2
    DEFAULT = ALRU


class MetadataLayout(IntEnum):
    STRIPING = 0
    SEQUENTIAL = 1
    DEFAULT = STRIPING


class Cache:
    DEFAULT_ID = 0
    DEFAULT_BACKFILL_QUEUE_SIZE = 65536
    DEFAULT_BACKFILL_UNBLOCK = 60000
    DEFAULT_PT_UNALIGNED_IO = False
    DEFAULT_USE_SUBMIT_FAST = False

    def __init__(
        self,
        owner,
        cache_id: int = DEFAULT_ID,
        name: str = "",
        cache_mode: CacheMode = CacheMode.DEFAULT,
        eviction_policy: EvictionPolicy = EvictionPolicy.DEFAULT,
        cache_line_size: CacheLineSize = CacheLineSize.DEFAULT,
        metadata_layout: MetadataLayout = MetadataLayout.DEFAULT,
        metadata_volatile: bool = False,
        max_queue_size: int = DEFAULT_BACKFILL_QUEUE_SIZE,
        queue_unblock_size: int = DEFAULT_BACKFILL_UNBLOCK,
        locked: bool = True,
        pt_unaligned_io: bool = DEFAULT_PT_UNALIGNED_IO,
        use_submit_fast: bool = DEFAULT_USE_SUBMIT_FAST,
    ):

        self.owner = owner
        self.cache_line_size = cache_line_size
        self.cfg = CacheConfig(
            _id=cache_id,
            _name=name.encode("ascii") if name else None,
            _cache_mode=cache_mode,
            _eviction_policy=eviction_policy,
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
        self.queues = []

    def start_cache(self):
        status = self.owner.lib.ocf_mngt_cache_start(
            self.owner.ctx_handle, byref(self.cache_handle), byref(self.cfg)
        )
        if status:
            raise OcfError("Creating cache instance failed", status)
        self.owner.caches += [self]

    def configure_device(
        self, device, force=False, perform_test=False, cache_line_size=None
    ):
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
        self, device, force=False, perform_test=False, cache_line_size=None,
    ):
        self.configure_device(device, force, perform_test, cache_line_size)

        status = device.owner.lib.ocf_mngt_cache_attach(
            self.cache_handle, byref(self.dev_cfg)
        )
        if status:
            raise OcfError("Attaching cache device failed", status)

    def load_cache(self, device):
        self.configure_device(device)

        status = device.owner.lib.ocf_mngt_cache_load(
            self.owner.ctx_handle,
            byref(self.cache_handle),
            byref(self.cfg),
            byref(self.dev_cfg),
        )
        if status:
            raise OcfError("Loading cache device failed", status)

    @classmethod
    def load_from_device(cls, device, name=""):
        c = cls(name=name, owner=device.owner)
        c.load_cache(device)
        return c

    @classmethod
    def start_on_device(cls, device, **kwargs):
        c = cls(locked=True, owner=device.owner, **kwargs)

        c.start_cache()
        c.attach_device(device, force=True)
        return c

    def _get_and_lock(self, read=True):
        status = self.owner.lib.ocf_mngt_cache_get(self.cache_handle)
        if status:
            raise OcfError("Couldn't get cache instance", status)

        if read:
            status = self.owner.lib.ocf_mngt_cache_read_lock(self.cache_handle)
        else:
            status = self.owner.lib.ocf_mngt_cache_lock(self.cache_handle)

        if status:
            self.owner.lib.ocf_mngt_cache_put(self.cache_handle)
            raise OcfError("Couldn't lock cache instance", status)

    def _put_and_unlock(self, read=True):
        if read:
            self.owner.lib.ocf_mngt_cache_read_unlock(self.cache_handle)
        else:
            self.owner.lib.ocf_mngt_cache_unlock(self.cache_handle)

        self.owner.lib.ocf_mngt_cache_put(self.cache_handle)

    def get_and_read_lock(self):
        self._get_and_lock(True)

    def get_and_write_lock(self):
        self._get_and_lock(False)

    def put_and_read_unlock(self):
        self._put_and_unlock(True)

    def put_and_write_unlock(self):
        self._put_and_unlock(False)

    def add_core(self, core: Core):
        self.get_and_write_lock()

        status = self.owner.lib.ocf_mngt_cache_add_core(
            self.cache_handle, byref(core.get_handle()), byref(core.get_cfg())
        )

        if status:
            self.put_and_write_unlock()
            raise OcfError("Failed adding core", status)

        core.cache = self

        self.put_and_write_unlock()

    def get_stats(self):
        cache_info = CacheInfo()
        usage = UsageStats()
        req = RequestsStats()
        block = BlocksStats()
        errors = ErrorsStats()

        self.get_and_read_lock()

        status = self.owner.lib.ocf_cache_get_info(self.cache_handle, byref(cache_info))
        if status:
            self.put_and_read_unlock()
            raise OcfError("Failed getting cache info", status)

        status = self.owner.lib.ocf_stats_collect_cache(
            self.cache_handle, byref(usage), byref(req), byref(block), byref(errors)
        )
        if status:
            self.put_and_read_unlock()
            raise OcfError("Failed getting stats", status)

        line_size = CacheLineSize(cache_info.cache_line_size)

        self.put_and_read_unlock()
        return {
            "conf": {
                "attached": cache_info.attached,
                "volume_type": self.owner.volume_types[cache_info.volume_type],
                "size": CacheLines(cache_info.size, line_size),
                "inactive": {
                    "occupancy": CacheLines(cache_info.inactive.occupancy, line_size),
                    "dirty": CacheLines(cache_info.inactive.dirty, line_size),
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
                "cache_line_size": line_size,
                "flushed": CacheLines(cache_info.flushed, line_size),
                "core_count": cache_info.core_count,
                "metadata_footprint": Size(cache_info.metadata_footprint),
                "metadata_end_offset": Size(cache_info.metadata_end_offset),
            },
            "block": struct_to_dict(block),
            "req": struct_to_dict(req),
            "usage": struct_to_dict(usage),
            "errors": struct_to_dict(errors),
        }

    def reset_stats(self):
        self.owner.lib.ocf_core_stats_initialize_all(self.cache_handle)

    def get_default_queue(self):
        if not self.queues:
            raise Exception("No queues added for cache")

        return self.queues[0]


    def stop(self):
        self.get_and_write_lock()

        status = self.owner.lib.ocf_mngt_cache_stop(self.cache_handle)
        if status:
            self.put_and_write_unlock()
            raise OcfError("Failed stopping cache", status)

        self.put_and_write_unlock()
        self.owner.caches.remove(self)
