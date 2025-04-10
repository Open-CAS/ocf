#
# Copyright(c) 2019-2022 Intel Corporation
# Copyright(c) 2023-2024 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import (
    POINTER,
    c_void_p,
    c_uint32,
    c_char_p,
    create_string_buffer,
    memmove,
    memset,
    Structure,
    CFUNCTYPE,
    c_int,
    c_uint8,
    c_uint,
    c_uint64,
    sizeof,
    cast,
    string_at,
)
from hashlib import md5
import weakref
from enum import IntEnum
import warnings

from .io import Io, IoOps, IoDir
from .queue import Queue
from .shared import OcfErrorCode, Uuid
from ..ocf import OcfLib
from ..utils import print_buffer, Size as S
from .data import Data
from .queue import Queue


class IoFlags(IntEnum):
    FLUSH = 1


class VolumeCaps(Structure):
    _fields_ = [("_atomic_writes", c_uint32, 1)]


class VolumeOps(Structure):
    SUBMIT_IO = CFUNCTYPE(None, POINTER(Io))
    SUBMIT_FLUSH = CFUNCTYPE(None, c_void_p)
    SUBMIT_METADATA = CFUNCTYPE(None, c_void_p)
    SUBMIT_DISCARD = CFUNCTYPE(None, c_void_p)
    SUBMIT_WRITE_ZEROES = CFUNCTYPE(None, c_void_p)
    FORWARD_IO = CFUNCTYPE(None, c_void_p, c_uint64, c_int, c_uint64, c_uint64, c_uint64)
    FORWARD_FLUSH = CFUNCTYPE(None, c_void_p, c_uint64)
    FORWARD_DISCARD = CFUNCTYPE(None, c_void_p, c_uint64, c_uint64, c_uint64)
    FORWARD_WRITE_ZEROS = CFUNCTYPE(None, c_void_p, c_uint64, c_uint64, c_uint64)
    FORWARD_METADATA = CFUNCTYPE(None, c_void_p, c_uint64, c_int, c_uint64, c_uint64, c_uint64)
    FORWARD_IO_SIMPLE = CFUNCTYPE(None, c_void_p, c_uint64, c_int, c_uint64, c_uint64)
    ON_INIT = CFUNCTYPE(c_int, c_void_p)
    ON_DEINIT = CFUNCTYPE(None, c_void_p)
    OPEN = CFUNCTYPE(c_int, c_void_p, c_void_p)
    CLOSE = CFUNCTYPE(None, c_void_p)
    GET_MAX_IO_SIZE = CFUNCTYPE(c_uint, c_void_p)
    GET_LENGTH = CFUNCTYPE(c_uint64, c_void_p)
    COMPOSITE_VOLUME_ADD = CFUNCTYPE(c_int, c_void_p, c_uint8, c_void_p, c_void_p)
    COMPOSITE_VOLUME_ATTACH_MEMBER = CFUNCTYPE(c_int, c_void_p, c_void_p, c_uint8, c_void_p)
    COMPOSITE_VOLUME_DETACH_MEMBER = CFUNCTYPE(c_int, c_void_p, c_uint8)

    _fields_ = [
        ("_submit_io", SUBMIT_IO),
        ("_submit_flush", SUBMIT_FLUSH),
        ("_submit_metadata", SUBMIT_METADATA),
        ("_submit_discard", SUBMIT_DISCARD),
        ("_submit_write_zeroes", SUBMIT_WRITE_ZEROES),
        ("_forward_io", FORWARD_IO),
        ("_forward_flush", FORWARD_FLUSH),
        ("_forward_discard", FORWARD_DISCARD),
        ("_forward_write_zeros", FORWARD_WRITE_ZEROS),
        ("_forward_metadata", FORWARD_METADATA),
        ("_forward_io_simple", FORWARD_IO_SIMPLE),
        ("_on_init", ON_INIT),
        ("_on_deinit", ON_DEINIT),
        ("_open", OPEN),
        ("_close", CLOSE),
        ("_get_length", GET_LENGTH),
        ("_get_max_io_size", GET_MAX_IO_SIZE),
        ("_composite_volume_add", COMPOSITE_VOLUME_ADD),
        ("_composite_volume_attach_member", COMPOSITE_VOLUME_ATTACH_MEMBER),
        ("_composite_volume_detach_member", COMPOSITE_VOLUME_DETACH_MEMBER),
    ]


class VolumeProperties(Structure):
    _fields_ = [
        ("_name", c_char_p),
        ("_volume_priv_size", c_uint32),
        ("_caps", VolumeCaps),
        ("_deinit", c_char_p),
        ("_ops_", VolumeOps),
    ]


VOLUME_POISON = 0x13


class Volume:
    _instances_ = {}
    _uuid_ = weakref.WeakValueDictionary()
    _ops_ = {}
    _props_ = {}

    @classmethod
    def get_ops(cls):
        if cls in Volume._ops_:
            return Volume._ops_[cls]

        @VolumeOps.FORWARD_IO
        def _forward_io(volume, token, rw, addr, nbytes, offset):
            Volume.get_instance(volume).forward_io(token, rw, addr, nbytes, offset)

        @VolumeOps.FORWARD_FLUSH
        def _forward_flush(volume, token):
            Volume.get_instance(volume).forward_flush(token)

        @VolumeOps.FORWARD_DISCARD
        def _forward_discard(volume, token, addr, nbytes):
            Volume.get_instance(volume).forward_discard(token, addr, nbytes)

        @VolumeOps.ON_INIT
        def _on_init(ref):
            return 0

        @VolumeOps.ON_DEINIT
        def _on_deinit(ref):
            return

        @VolumeOps.OPEN
        def _open(ref, params):
            uuid_ptr = cast(lib.ocf_volume_get_uuid(ref), POINTER(Uuid))
            uuid = str(uuid_ptr.contents._data, encoding="ascii")
            try:
                volume = Volume.get_by_uuid(uuid)
            except:  # noqa E722 TODO:Investigate whether this really should be so broad
                warnings.warn("Tried to access unallocated volume {}".format(uuid))
                return -1

            ret = volume.open()
            if not ret:
                Volume._instances_[ref] = volume
                volume.handle = ref

            return ret


        @VolumeOps.CLOSE
        def _close(ref):
            volume = Volume.get_instance(ref)

            del Volume._instances_[volume.handle]
            volume.handle = None

            volume.close()

        @VolumeOps.GET_MAX_IO_SIZE
        def _get_max_io_size(ref):
            return Volume.get_instance(ref).get_max_io_size()

        @VolumeOps.GET_LENGTH
        def _get_length(ref):
            return Volume.get_instance(ref).get_length()

        @VolumeOps.COMPOSITE_VOLUME_ADD
        def _composite_volume_add(ref):
            raise NotImplementedError

        @VolumeOps.COMPOSITE_VOLUME_ATTACH_MEMBER
        def _composite_volume_attach_member(ref):
            raise NotImplementedError

        @VolumeOps.COMPOSITE_VOLUME_DETACH_MEMBER
        def _composite_volume_detach_member(ref):
            raise NotImplementedError

        Volume._ops_[cls] = VolumeOps(
            _forward_io=_forward_io,
            _forward_flush=_forward_flush,
            _forward_discard=_forward_discard,
            _open=_open,
            _close=_close,
            _get_max_io_size=_get_max_io_size,
            _get_length=_get_length,
            _on_init=_on_init,
            _on_deinit=_on_deinit,
            _composite_volume_add=_composite_volume_add,
            _composite_volume_attach_member=_composite_volume_attach_member,
            _composite_volume_detach_member=_composite_volume_detach_member,
        )

        return Volume._ops_[cls]

    def open(self):
        if self.opened:
            return -OcfErrorCode.OCF_ERR_NOT_OPEN_EXC

        self.opened = True

        return 0

    def close(self):
        if not self.opened:
            return

        self.opened = False

    @classmethod
    def get_io_ops(cls):
        return IoOps(_set_data=cls._io_set_data, _get_data=cls._io_get_data)

    @classmethod
    def get_props(cls):
        if cls in Volume._props_:
            return Volume._props_[cls]

        Volume._props_[cls] = VolumeProperties(
            _name=str(cls.__name__).encode("ascii"),
            _volume_priv_size=0,
            _caps=VolumeCaps(_atomic_writes=0),
            _ops_=cls.get_ops(),
            _deinit=0,
        )
        return Volume._props_[cls]

    def get_copy(self):
        raise NotImplementedError

    @classmethod
    def get_instance(cls, ref):
        if ref not in cls._instances_:
            warnings.warn(f"tried to access volume ref {ref} but it's gone")
            return None

        return cls._instances_[ref]

    @classmethod
    def get_by_uuid(cls, uuid):
        return cls._uuid_[uuid]

    def __init__(self, uuid=None):
        if uuid:
            if uuid in type(self)._uuid_:
                raise Exception("Volume with uuid {} already created".format(uuid))
            self.uuid = uuid
        else:
            self.uuid = str(id(self))

        type(self)._uuid_[self.uuid] = self

        self.reset_stats()
        self.is_online = True
        self.opened = False
        self.handle = None

    def get_length(self):
        raise NotImplementedError

    def get_max_io_size(self):
        raise NotImplementedError

    def get_stats(self):
        return self.stats

    def reset_stats(self):
        self.stats = {IoDir.WRITE: 0, IoDir.READ: 0}

    def inc_stats(self, _dir):
        self.stats[_dir] += 1

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        raise NotImplementedError

    def md5(self):
        raise NotImplementedError

    def offline(self):
        self.is_online = False

    def online(self):
        self.is_online = True

    def _reject_forward(self, token):
        Io.forward_end(token, -OcfErrorCode.OCF_ERR_IO)

    def forward_io(self, token, rw, addr, nbytes, offset):
        if self.is_online:
            self.inc_stats(IoDir(rw))
            self.do_forward_io(token, rw, addr, nbytes, offset)
        else:
            self._reject_forward(token)

    def forward_flush(self, token):
        if self.is_online:
            self.do_forward_flush(token)
        else:
            self._reject_forward(token)

    def forward_discard(self, token, addr, nbytes):
        if self.is_online:
            self.do_forward_discard(token, addr, nbytes)
        else:
            self._reject_forward(token)

    def new_io(
        self, queue: Queue, addr: int, length: int, direction: IoDir, io_class: int, flags: int,
    ):
        io = lib.ocf_volume_new_io(
            self.handle,
            queue.handle if queue else c_void_p(),
            addr,
            length,
            direction,
            io_class,
            flags,
        )
        return Io.from_pointer(io)


class RamVolume(Volume):
    props = None

    def __init__(self, size: S, uuid=None):
        super().__init__(uuid)
        self.size = size
        self.data = create_string_buffer(int(self.size))
        memset(self.data, VOLUME_POISON, self.size)
        self.data_ptr = cast(self.data, c_void_p).value

    def get_copy(self):
        new_volume = RamVolume(self.size)
        memmove(new_volume.data, self.data, self.size)
        return new_volume

    def get_length(self):
        return self.size

    def resize(self, size):
        self.size = size
        self.data = create_string_buffer(int(self.size))
        memset(self.data, VOLUME_POISON, self.size)
        self.data_ptr = cast(self.data, c_void_p).value

    def get_max_io_size(self):
        return S.from_KiB(128)

    def do_forward_io(self, token, rw, addr, nbytes, offset):
        try:
            if rw == IoDir.WRITE:
                src_ptr = cast(lib.ocf_forward_get_data(token), c_void_p)
                src = Data.get_instance(src_ptr.value).handle.value + offset
                dst = self.data_ptr + addr
            elif rw == IoDir.READ:
                dst_ptr = cast(lib.ocf_forward_get_data(token), c_void_p)
                dst = Data.get_instance(dst_ptr.value).handle.value + offset
                src = self.data_ptr + addr

            memmove(dst, src, nbytes)

            Io.forward_end(token, 0)
        except Exception as e:  # noqa E722
            Io.forward_end(token, -OcfErrorCode.OCF_ERR_IO)

    def do_forward_flush(self, token):
        Io.forward_end(token, 0)

    def do_forward_discard(self, token, addr, nbytes):
        try:
            dst = self.data_ptr + addr
            memset(dst, 0, nbytes)

            Io.forward_end(token, 0)
        except:  # noqa E722
            Io.forward_end(token, -OcfErrorCode.OCF_ERR_NOT_SUPP)

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        if size == 0:
            size = int(self.size) - int(offset)

        print_buffer(self.data_ptr, size, ignore=ignore, **kwargs)

    def md5(self):
        m = md5()
        m.update(string_at(self.data_ptr, self.size))
        return m.hexdigest()

    def get_bytes(self):
        return string_at(self.data_ptr, self.size)


class ErrorDevice(Volume):
    def __init__(
        self,
        vol,
        error_sectors: set = None,
        error_seq_no: dict = None,
        data_only=False,
        armed=True,
        uuid=None,
        length_armed=False,
    ):
        self.vol = vol
        super().__init__(uuid)
        self.error_sectors = error_sectors or set()
        self.error_seq_no = error_seq_no or {IoDir.WRITE: -1, IoDir.READ: -1}
        self.data_only = data_only
        self.armed = armed
        self.length_armed = length_armed
        self.io_seq_no = {IoDir.WRITE: 0, IoDir.READ: 0}
        self.error = False

    def set_mapping(self, error_sectors: set):
        self.error_sectors = error_sectors

    def open(self):
        ret = self.vol.open()
        if ret:
            return ret
        return super().open()

    def close(self):
        super().close()
        self.vol.close()

    def should_forward_io(self, rw, addr):
        if not self.armed:
            return True
        direction = IoDir(rw)
        seq_no_match = (
            self.error_seq_no[direction] >= 0
            and self.error_seq_no[direction] <= self.io_seq_no[direction]
        )
        sector_match = addr in self.error_sectors

        self.io_seq_no[direction] += 1

        return not seq_no_match and not sector_match

    def complete_forward_with_error(self, token, rw=IoDir.WRITE):
        self.error = True
        direction = IoDir(rw)
        self.stats["errors"][direction] += 1
        Io.forward_end(token, -OcfErrorCode.OCF_ERR_IO)

    def do_forward_io(self, token, rw, addr, nbytes, offset):
        if self.should_forward_io(rw, addr):
            self.vol.do_forward_io(token, rw, addr, nbytes, offset)
        else:
            self.complete_forward_with_error(token, rw)

    def do_forward_flush(self, token):
        if self.data_only or self.should_forward_io(IoDir.WRITE, 0):
            self.vol.do_forward_flush(token)
        else:
            self.complete_forward_with_error(token)

    def do_forward_discard(self, token, addr, nbytes):
        if self.data_only or self.should_forward_io(IoDir.WRITE, addr):
            self.vol.do_forward_discard(token, addr, nbytes)
        else:
            self.complete_forward_with_error(token)

    def arm(self):
        self.armed = True

    def disarm(self):
        self.armed = False

    def arm_length(self):
        self.length_armed = True

    def disarm_length(self):
        self.length_armed = False

    def error_triggered(self):
        return self.error

    def reset_stats(self):
        self.vol.reset_stats()
        super().reset_stats()
        self.stats["errors"] = {IoDir.WRITE: 0, IoDir.READ: 0}

    def get_length(self):
        if self.length_armed:
            return 0
        return self.vol.get_length()

    def get_max_io_size(self):
        return self.vol.get_max_io_size()

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        return self.vol.dump(offset, size, ignore=ignore, **kwargs)

    def md5(self):
        return self.vol.md5()

    def get_copy(self):
        return self.vol.get_copy()

    def close(self):
        super().close()
        self.vol.close()


class TraceDevice(Volume):
    class IoType(IntEnum):
        Data = 1
        Flush = 2
        Discard = 3

    def __init__(self, vol, trace_fcn=None, uuid=None):
        self.vol = vol
        super().__init__(uuid)
        self.trace_fcn = trace_fcn

    def open(self):
        ret = self.vol.open()
        if ret:
            return ret
        return super().open()

    def close(self):
        super().close()
        self.vol.close()

    def _trace(self, io_type, rw, addr, nbytes, flags):
        submit = True

        if self.trace_fcn:
            submit = self.trace_fcn(self, io_type, rw, addr, nbytes, flags)

        return submit

    def do_forward_io(self, token, rw, addr, nbytes, offset):
        flags = lib.ocf_forward_get_flags(token)
        submit = self._trace(
            TraceDevice.IoType.Data,
            rw,
            addr,
            nbytes,
            flags
        )

        if submit:
            self.vol.do_forward_io(token, rw, addr, nbytes, offset)

    def do_forward_flush(self, token):
        flags = lib.ocf_forward_get_flags(token)
        submit = self._trace(
            TraceDevice.IoType.Flush,
            IoDir.WRITE,
            0,
            0,
            flags
        )

        if submit:
            self.vol.do_forward_flush(token)

    def do_forward_discard(self, token, addr, nbytes):
        flags = lib.ocf_forward_get_flags(token)
        submit = self._trace(
            TraceDevice.IoType.Discard,
            IoDir.WRITE,
            addr,
            nbytes,
            flags
        )

        if submit:
            self.vol.do_forward_discard(token, addr, nbytes)

    def get_length(self):
        return self.vol.get_length()

    def get_max_io_size(self):
        return self.vol.get_max_io_size()

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        return self.vol.dump(offset, size, ignore=ignore, **kwargs)

    def md5(self):
        return self.vol.md5()

    def get_copy(self):
        return self.vol.get_copy()


lib = OcfLib.getInstance()
lib.ocf_io_get_offset.restype = c_uint32
lib.ocf_io_get_volume.argtypes = [c_void_p]
lib.ocf_io_get_volume.restype = c_void_p
lib.ocf_io_get_data.argtypes = [c_void_p]
lib.ocf_io_get_data.restype = c_void_p
lib.ocf_forward_get_data.argtypes = [c_uint64]
lib.ocf_forward_get_data.restype = c_void_p
lib.ocf_forward_get_flags.argtypes = [c_uint64]
lib.ocf_forward_get_flags.restype = c_uint64
lib.ocf_volume_new_io.argtypes = [
    c_void_p,
    c_void_p,
    c_uint64,
    c_uint32,
    c_uint32,
    c_uint32,
    c_uint64,
]
lib.ocf_volume_new_io.restype = c_void_p
