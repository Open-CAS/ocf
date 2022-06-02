#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
#
from .ocf import OcfLib


def get_collision_segment_page_location(cache):
    lib = OcfLib.getInstance()
    return int(lib.ocf_get_collision_start_page_helper(cache))


def get_collision_segment_size(cache):
    lib = OcfLib.getInstance()
    return int(lib.ocf_get_collision_page_count_helper(cache))
