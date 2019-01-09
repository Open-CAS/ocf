#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import *
import logging
from datetime import timedelta

from ..ocf import OcfLib
from .shared import Uuid
from .volume import Volume
from .data import Data
from .io import Io, IoDir
from .stats.shared import *
from .stats.core import *
from ..utils import Size, struct_to_dict
from .queue import Queue


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

        self.device = device
        self.device_name = device.uuid
        self.core_id = core_id
        self.handle = c_void_p()
        self.cfg = CoreConfig(
            _uuid=Uuid(
                _data=cast(
                    create_string_buffer(self.device_name.encode("ascii")), c_char_p
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

        self.cache.get_and_lock(True)

        status = self.cache.owner.lib.ocf_stats_collect_core(
            self.handle, byref(usage), byref(req), byref(blocks), byref(errors)
        )
        if status:
            self.cache.put_and_unlock(True)
            raise OcfError("Failed collecting core stats", status)

        status = self.cache.owner.lib.ocf_core_get_stats(self.handle, byref(core_stats))
        if status:
            self.cache.put_and_unlock(True)
            raise OcfError("Failed getting core stats", status)

        self.cache.put_and_unlock(True)
        return {
            "size": Size(core_stats.core_size_bytes),
            "dirty_for": timedelta(seconds=core_stats.dirty_for),
            "usage": struct_to_dict(usage),
            "req": struct_to_dict(req),
            "blocks": struct_to_dict(blocks),
            "errors": struct_to_dict(errors),
        }

    def reset_stats(self):
        self.cache.owner.lib.ocf_core_stats_initialize(self.handle)

    def exp_obj_md5(self):
        logging.getLogger("pyocf").warning(
            "Reading whole exported object! This disturbs statistics values"
        )
        read_buffer = Data(self.device.size)
        io = self.new_io()
        io.configure(0, read_buffer.size, IoDir.READ, 0, 0)
        io.set_data(read_buffer)
        io.set_queue(self.cache.get_default_queue())
        io.submit()
        return read_buffer.md5()


lib = OcfLib.getInstance()
lib.ocf_core_get_volume.restype = c_void_p
lib.ocf_volume_new_io.argtypes = [c_void_p]
lib.ocf_volume_new_io.restype = c_void_p
