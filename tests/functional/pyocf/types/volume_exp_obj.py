#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import logging
from ctypes import c_int, c_void_p, CFUNCTYPE, byref, c_uint32, c_uint64, cast, POINTER

from ..ocf import OcfLib
from .volume import Volume, VOLUME_POISON
from pyocf.utils import Size
from pyocf.types.data import Data
from pyocf.types.io import IoDir, Io
from pyocf.types.shared import OcfCompletion


class OcfInternalVolume(Volume):
    def __init__(self, parent, uuid=None):
        super().__init__(uuid)
        self.parent = parent

    def __alloc_io(self, addr, _bytes, _dir, _class, _flags):
        vol = self.parent.get_front_volume()
        queue = self.parent.get_default_queue()  # TODO multiple queues?
        return vol.new_io(queue, addr, _bytes, _dir, _class, _flags)

    def _alloc_io(self, io):
        exp_obj_io = self.__alloc_io(
            io.contents._addr,
            io.contents._bytes,
            io.contents._dir,
            io.contents._class,
            io.contents._flags,
        )

        lib = OcfLib.getInstance()
        cdata = OcfLib.getInstance().ocf_io_get_data(io)
        OcfLib.getInstance().ocf_io_set_data(byref(exp_obj_io), cdata, 0)

        def cb(error):
            nonlocal io
            io = cast(io, POINTER(Io))
            io.contents._end(io, error)

        exp_obj_io.callback = cb

        return exp_obj_io

    def get_length(self):
        return Size.from_B(OcfLib.getInstance().ocf_volume_get_length(self.handle))

    def get_max_io_size(self):
        return Size.from_B(OcfLib.getInstance().ocf_volume_get_max_io_size(self.handle))

    def do_submit_io(self, io):
        io = self._alloc_io(io)
        io.submit()

    def do_submit_flush(self, flush):
        io = self._alloc_io(flush)
        io.submit_flush()

    def do_submit_discard(self, discard):
        io = self._alloc_io(discard)
        io.submit_discard()

    def _read(self, offset=0, size=0):
        if size == 0:
            size = self.get_length().B - offset
        exp_obj_io = self.__alloc_io(offset, size, IoDir.READ, 0, 0)
        completion = OcfCompletion([("err", c_int)])
        exp_obj_io.callback = completion
        data = Data.from_bytes(bytes(size))
        exp_obj_io.set_data(data)
        exp_obj_io.submit()
        completion.wait()
        error = completion.results["err"]
        if error:
            raise Exception("error reading exported object for dump")
        return data

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        data = self._read(offset, size)
        data.dump(ignore=ifnore, **kwargs)

    def md5(self):
        raise NotImplementedError

    def _exp_obj_md5(self, read_size):
        logging.getLogger("pyocf").warning(
            "Reading whole exported object! This disturbs statistics values"
        )

        read_buffer_all = Data(self.parent.device.size)

        read_buffer = Data(read_size)

        position = 0
        while position < read_buffer_all.size:
            io = self.new_io(self.parent.get_default_queue(), position, read_size, IoDir.READ, 0, 0)
            io.set_data(read_buffer)

            cmpl = OcfCompletion([("err", c_int)])
            io.callback = cmpl.callback
            io.submit()
            cmpl.wait()

            if cmpl.results["err"]:
                raise Exception("Error reading whole exported object")

            read_buffer_all.copy(read_buffer, position, 0, read_size)
            position += read_size

        return read_buffer_all.md5()

    def open(self):
        handle = self.get_c_handle()
        return Volume.s_open(handle, self)

    def close(self):
        return Volume.s_close(self)


lib = OcfLib.getInstance()
lib.ocf_volume_get_max_io_size.argtypes = [c_void_p]
lib.ocf_volume_get_max_io_size.restype = c_uint32
lib.ocf_volume_get_length.argtypes = [c_void_p]
lib.ocf_volume_get_length.restype = c_uint64
lib.ocf_io_get_data.argtypes = [POINTER(Io)]
lib.ocf_io_get_data.restype = c_void_p
