#
# Copyright(c) 2022 Intel Corporation
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

from .volume import Volume, VOLUME_POISON
from .io import Io, IoDir


class ReplicatedVolume(Volume):
    def __init__(self, primary: Volume, secondary: Volume, uuid=None):
        super().__init__(uuid)
        self.primary = primary
        self.secondary = secondary

    def open(self):
        ret = self.primary.open()
        if ret:
            raise Exception(f"Couldn't open primary volume. ({ret})")
        ret = self.secondary.open()
        if ret:
            raise Exception(f"Couldn't open secondary volume. ({ret})")

        if self.secondary.get_max_io_size() < self.primary.get_max_io_size():
            raise Exception("secondary volume max io size too small")
        if self.secondary.get_length() < self.primary.get_length():
            raise Exception("secondary volume size too small")

        return super().open()

    def close(self):
        super().close()
        self.primary.close()
        self.secondary.close()

    def get_length(self):
        return self.primary.get_length()

    def get_max_io_size(self):
        return self.primary.get_max_io_size()

    def do_forward_io(self, token, rw, addr, nbytes, offset):
        if rw == IoDir.WRITE:
            Io.forward_get(token)
            self.secondary.do_forward_io(token, rw, addr, nbytes, offset)
        self.primary.do_forward_io(token, rw, addr, nbytes, offset)

    def do_forward_flush(self, token):
        Io.forward_get(token)
        self.secondary.do_forward_flush(token)
        self.primary.do_forward_flush(token)

    def do_forward_discard(self, token, addr, nbytes):
        Io.forward_get(token)
        self.secondary.do_forward_discard(token, addr, nbytes)
        self.primary.do_forward_discard(token, addr, nbytes)

    def dump(self, offset=0, size=0, ignore=VOLUME_POISON, **kwargs):
        self.primary.dump()

    def md5(self):
        return self.primary.md5()
