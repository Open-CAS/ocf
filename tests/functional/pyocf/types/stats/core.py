
#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

from ctypes import c_uint32, c_uint64, Structure

from .shared import OcfStatsReq, OcfStatsBlock, OcfStatsDebug, OcfStatsError


class CoreStats(Structure):
    _fields_ = [
        ("core_size", c_uint64),
        ("core_size_bytes", c_uint64),
        ("cache_occupancy", c_uint32),
        ("dirty", c_uint32),
        ("flushed", c_uint32),
        ("dirty_for", c_uint32),
        ("read_reqs", OcfStatsReq),
        ("write_reqs", OcfStatsReq),
        ("cache_volume", OcfStatsBlock),
        ("core_volume", OcfStatsBlock),
        ("core", OcfStatsBlock),
        ("cache_errors", OcfStatsError),
        ("core_errors", OcfStatsError),
        ("debug_stat", OcfStatsDebug),
        ("seq_cutoff_threshold", c_uint32),
        ("seq_cutoff_policy", c_uint32),
    ]
