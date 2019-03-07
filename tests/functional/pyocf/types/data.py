#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import *
from enum import IntEnum
from hashlib import md5

from .shared import SharedOcfObject
from ..utils import print_buffer


class DataSeek(IntEnum):
    BEGIN = 0
    CURRENT = 1


class DataOps(Structure):
    ALLOC = CFUNCTYPE(c_void_p, c_uint32)
    FREE = CFUNCTYPE(None, c_void_p)
    MLOCK = CFUNCTYPE(c_int, c_void_p)
    MUNLOCK = CFUNCTYPE(None, c_void_p)
    READ = CFUNCTYPE(c_uint32, c_void_p, c_void_p, c_uint32)
    WRITE = CFUNCTYPE(c_uint32, c_void_p, c_void_p, c_uint32)
    ZERO = CFUNCTYPE(c_uint32, c_void_p, c_uint32)
    SEEK = CFUNCTYPE(c_uint32, c_void_p, c_uint32, c_uint32)
    COPY = CFUNCTYPE(c_uint64, c_void_p, c_void_p, c_uint64, c_uint64, c_uint64)
    SECURE_ERASE = CFUNCTYPE(None, c_void_p)

    _fields_ = [
        ("_alloc", ALLOC),
        ("_free", FREE),
        ("_mlock", MLOCK),
        ("_munlock", MUNLOCK),
        ("_read", READ),
        ("_write", WRITE),
        ("_zero", ZERO),
        ("_seek", SEEK),
        ("_copy", COPY),
        ("_secure_erase", SECURE_ERASE),
    ]


class Data(SharedOcfObject):
    PAGE_SIZE = 4096

    _instances_ = {}

    _fields_ = [("data", c_void_p)]

    def __init__(self, byte_count: int):
        self.size = byte_count
        self.position = 0
        self.buffer = create_string_buffer(int(self.size))
        self.data = cast(self.buffer, c_void_p)
        memset(self.data, 0, self.size)
        type(self)._instances_[self.data] = self
        self._as_parameter_ = self.data

        super().__init__()

    @classmethod
    def get_ops(cls):
        return DataOps(
            _alloc=cls._alloc,
            _free=cls._free,
            _mlock=cls._mlock,
            _munlock=cls._munlock,
            _read=cls._read,
            _write=cls._write,
            _zero=cls._zero,
            _seek=cls._seek,
            _copy=cls._copy,
            _secure_erase=cls._secure_erase,
        )

    @classmethod
    def pages(cls, pages: int):
        return cls(pages * Data.PAGE_SIZE)

    @classmethod
    def from_bytes(cls, source: bytes):
        d = cls(len(source))

        memmove(d.data, cast(source, c_void_p), len(source))

        return d

    @classmethod
    def from_string(cls, source: str, encoding: str = "ascii"):
        return cls.from_bytes(bytes(source, encoding))

    def __str__(self):
        char_array = cast(self.data, c_char_p)
        return str(char_array.value, "ascii")

    def __wstr__(self):
        char_array = cast(self.data, c_wchar_p)
        return str(char_array.value, "utf-8")

    def set_data(self, contents):
        if len(contents) > self.size:
            raise Exception("Data too big to fit into allocated buffer")

        memmove(self.data, cast(contents, c_void_p), len(contents))
        self.position = 0

    @staticmethod
    @DataOps.ALLOC
    def _alloc(pages):
        data = Data.pages(pages)
        return data.data

    @staticmethod
    @DataOps.FREE
    def _free(data):
        Data.del_object(data)

    @staticmethod
    @DataOps.MLOCK
    def _mlock(ref):
        return Data.get_instance(ref).mlock()

    @staticmethod
    @DataOps.MUNLOCK
    def _munlock(ref):
        Data.get_instance(ref).munlock()

    @staticmethod
    @DataOps.READ
    def _read(dst, src, size):
        return Data.get_instance(src).read(dst, size)

    @staticmethod
    @DataOps.WRITE
    def _write(dst, src, size):
        return Data.get_instance(dst).write(src, size)

    @staticmethod
    @DataOps.ZERO
    def _zero(dst, size):
        return Data.get_instance(dst).zero(size)

    @staticmethod
    @DataOps.SEEK
    def _seek(dst, seek, size):
        return Data.get_instance(dst).seek(DataSeek(seek), size)

    @staticmethod
    @DataOps.COPY
    def _copy(dst, src, end, start, size):
        return Data.get_instance(dst).copy(Data.get_instance(src), end, start, size)

    @staticmethod
    @DataOps.SECURE_ERASE
    def _secure_erase(dst):
        Data.get_instance(dst).secure_erase()

    def read(self, dst, size):
        to_read = min(self.size - self.position, size)
        memmove(dst, self.data + self.position, to_read)
        return to_read

    def write(self, src, size):
        to_write = min(self.size - self.position, size)
        memmove(self.data + self.position, src, to_write)
        return to_write

    def mlock(self):
        return 0

    def munlock(self):
        pass

    def zero(self, size):
        to_zero = min(self.size - self.position, size)
        memset(self.data + self.position, 0, to_zero)
        return to_zero

    def seek(self, seek, size):
        if seek == DataSeek.CURRENT:
            to_move = min(self.size - self.position, size)
            self.position += to_move
        else:
            to_move = min(self.size, size)
            self.position = to_move

        return to_move

    def copy(self, src, end, start, size):
        return size

    def secure_erase(self):
        pass

    def dump(self):
        print_buffer(self.buffer, self.size)

    def md5(self):
        m = md5()
        m.update(string_at(self.data, self.size))
        return m.hexdigest()
