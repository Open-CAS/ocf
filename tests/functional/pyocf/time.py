#
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import c_uint64

from .ocf import OcfLib

SEC_IN_NS = 1_000_000_000


def advance_time(secs):
    lib = OcfLib.getInstance()
    offset = c_uint64.in_dll(lib, "ocf_env_tick_count_offset")
    offset.value += secs * SEC_IN_NS


def advance_time_ms(ms):
    lib = OcfLib.getInstance()
    offset = c_uint64.in_dll(lib, "ocf_env_tick_count_offset")
    offset.value += ms * 1_000_000


def reset_time():
    lib = OcfLib.getInstance()
    offset = c_uint64.in_dll(lib, "ocf_env_tick_count_offset")
    offset.value = 0
