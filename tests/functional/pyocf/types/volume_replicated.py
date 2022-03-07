#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from threading import Lock
from .volume import Volume, VOLUME_POISON
from .io import Io, IoDir
from ctypes import cast, c_void_p, CFUNCTYPE, c_int, POINTER, memmove, sizeof, pointer


class ReplicatedVolume(Volume):
    def __init__(self, primary: Volume, secondary: Volume, uuid=None):
        super().__init__(uuid)
        self.primary = primary
        self.secondary = secondary

        if secondary.get_max_io_size() < primary.get_max_io_size():
            raise Exception("secondary volume max io size too small")
        if secondary.get_length() < primary.get_length():
            raise Exception("secondary volume size too small")

    def do_open(self):
        ret = self.primary.do_open()
        if ret:
            return ret
        ret = self.secondary.do_open()
        if ret:
            self.primary.close()
        return ret

    def close(self):
        self.primary.close()
        self.secondary.close()

    def get_length(self):
        return self.primary.get_length()

    def get_max_io_size(self):
        return self.primary.get_max_io_size()

    def _prepare_io(self, io):
        original_cb = Io.END()
        pointer(original_cb)[0] = io.contents._end
        lock = Lock()
        error = 0
        io_remaining = 2

        @CFUNCTYPE(None, c_void_p, c_int)
        def cb(io, err):
            nonlocal io_remaining
            nonlocal error
            nonlocal original_cb
            nonlocal lock
            io = cast(io, POINTER(Io))

            with lock:
                if err:
                    error = err
                io_remaining -= 1
                finished = True if io_remaining == 0 else False
            if finished:
                io.contents._end = original_cb
                original_cb(io, error)

        io.contents._end = cb

    def do_submit_io(self, io):
        if io.contents._dir == IoDir.WRITE:
            self._prepare_io(io)
            self.primary.submit_io(io)
            self.secondary.submit_io(io)
        else:
            # for read just pass through down to primary
            # with original completion
            self.primary.submit_io(io)

    def do_submit_flush(self, flush):
        self._prepare_io(flush)
        self.primary.submit_flush(flush)
        self.secondary.submit_flush(flush)

    def do_submit_discard(self, discard):
        self._prepare_io(discard)
        self.primary.submit_discard(discard)
        self.secondary.submit_discard(discard)

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        self.primary.dump()

    def md5(self):
        return self.primary.md5()
