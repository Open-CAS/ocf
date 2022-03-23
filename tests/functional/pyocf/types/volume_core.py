#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from .core import Core
from .volume_exp_obj import ExpObjVolume
from .io import IoDir
from .volume import Volume


class CoreVolume(ExpObjVolume):
    def __init__(self, core, open=False, uuid=None):
        super().__init__(core, uuid)
        self.core = core
        self.lib = core.cache.owner.lib
        if open:
            self.open()

    def open(self):
        return Volume.open(
            self.lib.ocf_core_get_front_volume(self.core.handle),
            self
        )

    def md5(self):
        return self._exp_obj_md5(4096)
