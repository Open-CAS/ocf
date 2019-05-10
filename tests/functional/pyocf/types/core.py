#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import logging
from ctypes import (
    c_size_t,
    c_void_p,
    Structure,
    c_int,
    c_uint8,
    c_uint16,
    c_char_p,
    c_bool,
    c_uint32,
    cast,
    byref,
    create_string_buffer,
)
from datetime import timedelta

from .data import Data
from .io import Io, IoDir
from .shared import Uuid, OcfCompletion, OcfError, SeqCutOffPolicy
from .stats.core import CoreStats
from .stats.shared import UsageStats, RequestsStats, BlocksStats, ErrorsStats
from .volume import Volume
from ..ocf import OcfLib
from ..utils import Size, struct_to_dict


class UserMetadata(Structure):
    _fields_ = [("data", c_void_p), ("size", c_size_t)]


class CoreConfig(Structure):
    _fields_ = [
        ("_uuid", Uuid),
        ("_volume_type", c_uint8),
        ("_core_id", c_uint16),
        ("_name", c_char_p),
        ("_cache_id", c_uint16),
        ("_try_add", c_bool),
        ("_seq_cutoff_threshold", c_uint32),
        ("_user_metadata", UserMetadata),
    ]


class Core:
    DEFAULT_ID = 4096
    DEFAULT_SEQ_CUTOFF_THRESHOLD = 1024 * 1024

    def __init__(
        self,
        device: Volume,
        try_add: bool,
        name: str = "",
        core_id: int = DEFAULT_ID,
        seq_cutoff_threshold: int = DEFAULT_SEQ_CUTOFF_THRESHOLD,
    ):
        self.cache = None
        self.device = device
        self.device_name = device.uuid
        self.core_id = core_id
        self.handle = c_void_p()
        self.cfg = CoreConfig(
            _uuid=Uuid(
                _data=cast(
                    create_string_buffer(self.device_name.encode("ascii")),
                    c_char_p,
                ),
                _size=len(self.device_name) + 1,
            ),
            _core_id=self.core_id,
            _name=name.encode("ascii") if name else None,
            _volume_type=self.device.type_id,
            _try_add=try_add,
            _seq_cutoff_threshold=seq_cutoff_threshold,
            _user_metadata=UserMetadata(_data=None, _size=0),
        )

    @classmethod
    def using_device(cls, device, **kwargs):
        c = cls(device=device, try_add=False, **kwargs)

        return c

    def get_cfg(self):
        return self.cfg

    def get_handle(self):
        return self.handle

    def new_io(self):
        if not self.cache:
            raise Exception("Core isn't attached to any cache")

        io = OcfLib.getInstance().ocf_core_new_io_wrapper(self.handle)
        return Io.from_pointer(io)

    def new_core_io(self):
        lib = OcfLib.getInstance()
        core = lib.ocf_core_get_volume(self.handle)
        io = lib.ocf_volume_new_io(core)
        return Io.from_pointer(io)

    def get_stats(self):
        core_stats = CoreStats()
        usage = UsageStats()
        req = RequestsStats()
        blocks = BlocksStats()
        errors = ErrorsStats()

        self.cache.read_lock()
        status = self.cache.owner.lib.ocf_stats_collect_core(
            self.handle, byref(usage), byref(req), byref(blocks), byref(errors)
        )
        if status:
            self.cache.read_unlock()
            raise OcfError("Failed collecting core stats", status)

        status = self.cache.owner.lib.ocf_core_get_stats(
            self.handle, byref(core_stats)
        )
        if status:
            self.cache.read_unlock()
            raise OcfError("Failed getting core stats", status)

        self.cache.read_unlock()
        return {
            "size": Size(core_stats.core_size_bytes),
            "dirty_for": timedelta(seconds=core_stats.dirty_for),
            "seq_cutoff_policy": SeqCutOffPolicy(core_stats.seq_cutoff_policy),
            "seq_cutoff_threshold": core_stats.seq_cutoff_threshold,
            "usage": struct_to_dict(usage),
            "req": struct_to_dict(req),
            "blocks": struct_to_dict(blocks),
            "errors": struct_to_dict(errors),
        }

    def set_seq_cut_off_policy(self, policy: SeqCutOffPolicy):
        self.cache.write_lock()

        status = self.cache.owner.lib.ocf_mngt_core_set_seq_cutoff_policy(
            self.handle, policy
        )
        if status:
            self.cache.write_unlock()
            raise OcfError("Error setting core seq cut off policy", status)

        self.cache.write_unlock()

    def reset_stats(self):
        self.cache.owner.lib.ocf_core_stats_initialize(self.handle)

    def exp_obj_md5(self):
        logging.getLogger("pyocf").warning(
            "Reading whole exported object! This disturbs statistics values"
        )
        cache_line_size = int(self.cache.get_stats()['conf']['cache_line_size'])
        read_buffer_all = Data(self.device.size)

        read_buffer = Data(cache_line_size)

        position = 0
        while position < read_buffer_all.size:

            io = self.new_io()
            io.configure(position, cache_line_size, IoDir.READ, 0, 0)
            io.set_data(read_buffer)
            io.set_queue(self.cache.get_default_queue())

            cmpl = OcfCompletion([("err", c_int)])
            io.callback = cmpl.callback
            io.submit()
            cmpl.wait()

            if cmpl.results["err"]:
                raise Exception("Error reading whole exported object")

            read_buffer_all.copy(read_buffer, position, 0, cache_line_size)
            position += cache_line_size

        return read_buffer_all.md5()


lib = OcfLib.getInstance()
lib.ocf_core_get_volume.restype = c_void_p
lib.ocf_volume_new_io.argtypes = [c_void_p]
lib.ocf_volume_new_io.restype = c_void_p
lib.ocf_core_get_volume.argtypes = [c_void_p]
lib.ocf_core_get_volume.restype = c_void_p
lib.ocf_mngt_core_set_seq_cutoff_policy.argtypes = [c_void_p, c_uint32]
lib.ocf_mngt_core_set_seq_cutoff_policy.restype = c_int
lib.ocf_stats_collect_core.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]
lib.ocf_stats_collect_core.restype = c_int
lib.ocf_core_get_stats.argtypes = [c_void_p, c_void_p]
lib.ocf_core_get_stats.restype = c_int
