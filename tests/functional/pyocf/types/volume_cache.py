#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import cast, POINTER

from .cache import Cache
from .io import Io
from .io import IoDir
from .volume_exp_obj import OcfInternalVolume
from .volume import Volume


class CacheVolume(OcfInternalVolume):
    def __init__(self, cache, open=False, uuid=None):
        super().__init__(cache, uuid)
        self.cache = cache
        self.lib = cache.owner.lib
        if open:
            self.open()

    def get_c_handle(self):
        return self.cache.get_c_front_volume()

    def md5(self):
        out = self.cache.get_conf()
        cache_line_size = int(out["cache_line_size"])
        return self._exp_obj_md5(cache_line_size)
