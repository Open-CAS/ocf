#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from .core import Core
from .volume_exp_obj import OcfInternalVolume
from .io import IoDir
from .volume import Volume


class CoreVolume(OcfInternalVolume):
    def __init__(self, core, open=False, uuid=None):
        super().__init__(core, uuid)
        self.core = core
        self.lib = core.cache.owner.lib
        if open:
            self.open()

    def get_c_handle(self):
        return self.core.get_c_front_volume()

    def md5(self):
        return self._exp_obj_md5(4096)
