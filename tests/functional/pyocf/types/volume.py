#
# Copyright(c) 2019-2022 Intel Corporation
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
    c_uint,
    c_uint64,
    sizeof,
    cast,
    string_at,
)
from hashlib import md5
import weakref
from enum import IntEnum

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
    ON_INIT = CFUNCTYPE(c_int, c_void_p)
    ON_DEINIT = CFUNCTYPE(None, c_void_p)
    OPEN = CFUNCTYPE(c_int, c_void_p, c_void_p)
    CLOSE = CFUNCTYPE(None, c_void_p)
    GET_MAX_IO_SIZE = CFUNCTYPE(c_uint, c_void_p)
    GET_LENGTH = CFUNCTYPE(c_uint64, c_void_p)

    _fields_ = [
        ("_submit_io", SUBMIT_IO),
        ("_submit_flush", SUBMIT_FLUSH),
        ("_submit_metadata", SUBMIT_METADATA),
        ("_submit_discard", SUBMIT_DISCARD),
        ("_submit_write_zeroes", SUBMIT_WRITE_ZEROES),
        ("_on_init", ON_INIT),
        ("_on_deinit", ON_DEINIT),
        ("_open", OPEN),
        ("_close", CLOSE),
        ("_get_length", GET_LENGTH),
        ("_get_max_io_size", GET_MAX_IO_SIZE),
    ]


class VolumeProperties(Structure):
    _fields_ = [
        ("_name", c_char_p),
        ("_io_priv_size", c_uint32),
        ("_volume_priv_size", c_uint32),
        ("_caps", VolumeCaps),
        ("_io_ops", IoOps),
        ("_deinit", c_char_p),
        ("_ops_", VolumeOps),
    ]


class VolumeIoPriv(Structure):
    _fields_ = [("_data", c_void_p), ("_offset", c_uint64)]


VOLUME_POISON = 0x13


class Volume:
    _instances_ = weakref.WeakValueDictionary()
    _uuid_ = weakref.WeakValueDictionary()
    _ops_ = {}
    _props_ = {}

    @classmethod
    def get_ops(cls):
        if cls in Volume._ops_:
            return Volume._ops_[cls]

        @VolumeOps.SUBMIT_IO
        def _submit_io(io):
            io_structure = cast(io, POINTER(Io))
            volume = Volume.get_instance(OcfLib.getInstance().ocf_io_get_volume(io_structure))

            volume.submit_io(io_structure)

        @VolumeOps.SUBMIT_FLUSH
        def _submit_flush(flush):
            io_structure = cast(flush, POINTER(Io))
            volume = Volume.get_instance(OcfLib.getInstance().ocf_io_get_volume(io_structure))

            volume.submit_flush(io_structure)

        @VolumeOps.SUBMIT_METADATA
        def _submit_metadata(meta):
            raise NotImplementedError

        @VolumeOps.SUBMIT_DISCARD
        def _submit_discard(discard):
            io_structure = cast(discard, POINTER(Io))
            volume = Volume.get_instance(OcfLib.getInstance().ocf_io_get_volume(io_structure))

            volume.submit_discard(io_structure)

        @VolumeOps.SUBMIT_WRITE_ZEROES
        def _submit_write_zeroes(write_zeroes):
            raise NotImplementedError

        @VolumeOps.ON_INIT
        def _on_init(ref):
            return 0

        @VolumeOps.ON_DEINIT
        def _on_deinit(ref):
            return

        @VolumeOps.OPEN
        def _open(ref, params):
            uuid_ptr = cast(OcfLib.getInstance().ocf_volume_get_uuid(ref), POINTER(Uuid))
            uuid = str(uuid_ptr.contents._data, encoding="ascii")
            try:
                volume = Volume.get_by_uuid(uuid)
            except:  # noqa E722 TODO:Investigate whether this really should be so broad
                print("Tried to access unallocated volume {}".format(uuid))
                print("{}".format(Volume._uuid_))
                return -1

            return Volume.s_open(ref, volume)

        @VolumeOps.CLOSE
        def _close(ref):
            volume = Volume.get_instance(ref)
            Volume.s_close(volume)

        @VolumeOps.GET_MAX_IO_SIZE
        def _get_max_io_size(ref):
            return Volume.get_instance(ref).get_max_io_size()

        @VolumeOps.GET_LENGTH
        def _get_length(ref):
            return Volume.get_instance(ref).get_length()

        Volume._ops_[cls] = VolumeOps(
            _submit_io=_submit_io,
            _submit_flush=_submit_flush,
            _submit_metadata=_submit_metadata,
            _submit_discard=_submit_discard,
            _submit_write_zeroes=_submit_write_zeroes,
            _open=_open,
            _close=_close,
            _get_max_io_size=_get_max_io_size,
            _get_length=_get_length,
            _on_init=_on_init,
            _on_deinit=_on_deinit,
        )

        return Volume._ops_[cls]

    @staticmethod
    def s_open(ref, volume):
        if volume.opened:
            return -OcfErrorCode.OCF_ERR_NOT_OPEN_EXC

        Volume._instances_[ref] = volume
        volume.handle = ref

        ret = volume.do_open()
        if ret == 0:
            volume.opened = True

        return ret

    @staticmethod
    def s_close(volume):
        if not volume.opened:
            return

        volume.do_close()
        volume.opened = False

        del Volume._instances_[volume.handle]
        volume.handle = None

    @classmethod
    def get_io_ops(cls):
        return IoOps(_set_data=cls._io_set_data, _get_data=cls._io_get_data)

    @classmethod
    def get_props(cls):
        if cls in Volume._props_:
            return Volume._props_[cls]

        Volume._props_[cls] = VolumeProperties(
            _name=str(cls.__name__).encode("ascii"),
            _io_priv_size=sizeof(VolumeIoPriv),
            _volume_priv_size=0,
            _caps=VolumeCaps(_atomic_writes=0),
            _ops_=cls.get_ops(),
            _io_ops=cls.get_io_ops(),
            _deinit=0,
        )
        return Volume._props_[cls]

    def get_copy(self):
        raise NotImplementedError

    @classmethod
    def get_instance(cls, ref):
        instance = cls._instances_[ref]
        if instance is None:
            print("tried to access {} but it's gone".format(ref))

        return instance

    @classmethod
    def get_by_uuid(cls, uuid):
        return cls._uuid_[uuid]

    @staticmethod
    @IoOps.SET_DATA
    def _io_set_data(io, data, offset):
        io_priv = cast(OcfLib.getInstance().ocf_io_get_priv(io), POINTER(VolumeIoPriv))
        data = Data.get_instance(data)
        io_priv.contents._offset = offset
        io_priv.contents._data = data.handle

        return 0

    @staticmethod
    @IoOps.GET_DATA
    def _io_get_data(io):
        io_priv = cast(OcfLib.getInstance().ocf_io_get_priv(io), POINTER(VolumeIoPriv))
        return io_priv.contents._data

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

    def do_open(self):
        return 0

    def do_close(self):
        pass

    def get_length(self):
        raise NotImplementedError

    def get_max_io_size(self):
        raise NotImplementedError

    def do_submit_flush(self, flush):
        raise NotImplementedError

    def do_submit_discard(self, discard):
        raise NotImplementedError

    def get_stats(self):
        return self.stats

    def reset_stats(self):
        self.stats = {IoDir.WRITE: 0, IoDir.READ: 0}

    def inc_stats(self, _dir):
        self.stats[_dir] += 1

    def do_submit_io(self, io):
        raise NotImplementedError

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        raise NotImplementedError

    def md5(self):
        raise NotImplementedError

    def offline(self):
        self.is_online = False

    def online(self):
        self.is_online = True

    def _reject_io(self, io):
        cast(io, POINTER(Io)).contents._end(io, -OcfErrorCode.OCF_ERR_IO)

    def submit_flush(self, io):
        if self.is_online:
            self.do_submit_flush(io)
        else:
            self._reject_io(io)

    def submit_io(self, io):
        if self.is_online:
            self.inc_stats(IoDir(io.contents._dir))
            self.do_submit_io(io)
        else:
            self._reject_io(io)

    def submit_discard(self, io):
        if self.is_online:
            self.do_submit_discard(io)
        else:
            self._reject_io(io)

    def new_io(
        self, queue: Queue, addr: int, length: int, direction: IoDir, io_class: int, flags: int,
    ):
        lib = OcfLib.getInstance()
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

    def do_submit_flush(self, flush):
        flush.contents._end(flush, 0)

    def do_submit_discard(self, discard):
        try:
            dst = self.data_ptr + discard.contents._addr
            memset(dst, 0, discard.contents._bytes)

            discard.contents._end(discard, 0)
        except:  # noqa E722
            discard.contents._end(discard, -OcfErrorCode.OCF_ERR_NOT_SUPP)

    def do_submit_io(self, io):
        flags = int(io.contents._flags)
        if flags & IoFlags.FLUSH:
            self.do_submit_flush(io)
            return

        try:
            io_priv = cast(OcfLib.getInstance().ocf_io_get_priv(io), POINTER(VolumeIoPriv))
            offset = io_priv.contents._offset

            if io.contents._dir == IoDir.WRITE:
                src_ptr = cast(OcfLib.getInstance().ocf_io_get_data(io), c_void_p)
                src = Data.get_instance(src_ptr.value).handle.value + offset
                dst = self.data_ptr + io.contents._addr
            elif io.contents._dir == IoDir.READ:
                dst_ptr = cast(OcfLib.getInstance().ocf_io_get_data(io), c_void_p)
                dst = Data.get_instance(dst_ptr.value).handle.value + offset
                src = self.data_ptr + io.contents._addr

            memmove(dst, src, io.contents._bytes)
            io_priv.contents._offset += io.contents._bytes

            io.contents._end(io, 0)
        except:  # noqa E722
            io.contents._end(io, -OcfErrorCode.OCF_ERR_IO)

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
    ):
        self.vol = vol
        super().__init__(uuid)
        self.error_sectors = error_sectors or set()
        self.error_seq_no = error_seq_no or {IoDir.WRITE: -1, IoDir.READ: -1}
        self.data_only = data_only
        self.armed = armed
        self.io_seq_no = {IoDir.WRITE: 0, IoDir.READ: 0}
        self.error = False

    def set_mapping(self, error_sectors: set):
        self.error_sectors = error_sectors

    def should_forward_io(self, io):
        if not self.armed:
            return True

        direction = IoDir(io.contents._dir)
        seq_no_match = (
            self.error_seq_no[direction] >= 0
            and self.error_seq_no[direction] <= self.io_seq_no[direction]
        )
        sector_match = io.contents._addr in self.error_sectors

        self.io_seq_no[direction] += 1

        return not seq_no_match and not sector_match

    def complete_with_error(self, io):
        self.error = True
        direction = IoDir(io.contents._dir)
        self.stats["errors"][direction] += 1
        io.contents._end(io, -OcfErrorCode.OCF_ERR_IO)

    def do_submit_io(self, io):
        if self.should_forward_io(io):
            self.vol.do_submit_io(io)
        else:
            self.complete_with_error(io)

    def do_submit_flush(self, flush):
        if self.data_only or self.should_forward_io(flush):
            self.vol.do_submit_flush(flush)
        else:
            self.complete_with_error(flush)

    def do_submit_discard(self, discard):
        if self.data_only or self.should_forward_io(discard):
            self.vol.do_submit_discard(discard)
        else:
            self.complete_with_error(discard)

    def arm(self):
        self.armed = True

    def disarm(self):
        self.armed = False

    def error_triggered(self):
        return self.error

    def reset_stats(self):
        self.vol.reset_stats()
        super().reset_stats()
        self.stats["errors"] = {IoDir.WRITE: 0, IoDir.READ: 0}

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


class TraceDevice(Volume):
    class IoType(IntEnum):
        Data = 1
        Flush = 2
        Discard = 3

    def __init__(self, vol, trace_fcn=None, uuid=None):
        self.vol = vol
        super().__init__(uuid)
        self.trace_fcn = trace_fcn

    def _trace(self, io, io_type):
        submit = True

        if self.trace_fcn:
            submit = self.trace_fcn(self, io, io_type)

        return submit

    def do_submit_io(self, io):
        submit = self._trace(io, TraceDevice.IoType.Data)

        if submit:
            self.vol.do_submit_io(io)

    def do_submit_flush(self, io):
        submit = self._trace(io, TraceDevice.IoType.Flush)

        if submit:
            self.vol.do_submit_flush(io)

    def do_submit_discard(self, io):
        submit = self._trace(io, TraceDevice.IoType.Discard)

        if submit:
            self.vol.do_submit_discard(io)

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
lib.ocf_io_get_priv.restype = POINTER(VolumeIoPriv)
lib.ocf_io_get_volume.argtypes = [c_void_p]
lib.ocf_io_get_volume.restype = c_void_p
lib.ocf_io_get_data.argtypes = [c_void_p]
lib.ocf_io_get_data.restype = c_void_p
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
