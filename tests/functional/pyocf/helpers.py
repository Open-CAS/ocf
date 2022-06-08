#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
#
from .ocf import OcfLib


def get_metadata_segment_page_location(cache, segment):
    lib = OcfLib.getInstance()
    return int(lib.ocf_get_metadata_segment_start_page(cache, segment))


def get_metadata_segment_size(cache, segment):
    lib = OcfLib.getInstance()
    return int(lib.ocf_get_metadata_segment_page_count(cache, segment))


def get_metadata_segment_elems_count(cache, segment):
    lib = OcfLib.getInstance()
    return int(lib.ocf_get_metadata_segment_elems_count(cache, segment))


def get_metadata_segment_elems_per_page(cache, segment):
    lib = OcfLib.getInstance()
    return int(lib.ocf_get_metadata_segment_elems_per_page(cache, segment))


def get_metadata_segment_elem_size(cache, segment):
    lib = OcfLib.getInstance()
    return int(lib.ocf_get_metadata_segment_elem_size(cache, segment))


def get_metadata_segment_is_flapped(cache, segment):
    lib = OcfLib.getInstance()
    return bool(lib.ocf_get_metadata_segment_is_flapped(cache, segment))


def get_composite_volume_type_id():
    lib = OcfLib.getInstance()
    return int(lib.ocf_get_composite_volume_type_id_helper())
