#
# Copyright(c) 2022 Intel Corporation
# Copyright(c) 2024 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#

from .volume_exp_obj import OcfInternalVolume
from .queue import Queue
from .io import Sync, IoDir
from .data import Data


class CoreVolume(OcfInternalVolume):
    def __init__(self, core, uuid=None):
        super().__init__(core, uuid)
        self.core = core
        self.lib = core.cache.owner.lib

    def get_c_handle(self):
        return self.core.get_c_front_volume()

    def md5(self):
        return self._exp_obj_md5(4096)

    def sync_io(
        self,
        queue: Queue,
        address: int,
        data: Data,
        direction: IoDir,
        io_class=0,
        flags=0,
        submit_func=Sync.submit,
    ):
        super().sync_io(queue, address, data, direction, io_class, flags, submit_func)
        self.core.cache.settle()
