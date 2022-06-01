#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
from ctypes import c_int

from pyocf.types.volume import RamVolume, ErrorDevice, TraceDevice, IoFlags
from pyocf.types.cvolume import CVolume
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.shared import OcfError, OcfCompletion
from pyocf.utils import Size as S


def test_create_composite_volume(pyocf_ctx):
    """
    title: Create composite volume.
    description: |
      Check that it is possible to create and destroy composite volume
      object.
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolume is added without an error.
    steps:
      - Create composite volume
      - Verify that no error occured
      - Add RamVolume as a subvolume
      - Verify that no error occured
      - Destroy composite volume
    requirements:
      - composite_volume::creation
      - composite_volume::adding_component_volume
    """
    cvol = CVolume(pyocf_ctx)
    vol = RamVolume(S.from_MiB(1))
    cvol.add(vol)
    cvol.destroy()


def test_add_subvolumes_of_different_types(pyocf_ctx):
    """
    title: Add subvolumes of different types.
    description: |
      Check that it is possible to add two subvolumes of different types to
      composite volume.
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolumes are added without an error.
    steps:
      - Create composite volume
      - Add RamVolume as a subvolume
      - Verify that no error occured
      - Add ErrorDevice as a subvolume
      - Verify that no error occured
      - Destroy composite volume
    requirements:
      - composite_volume::component_volume_types
    """
    vol1 = RamVolume(S.from_MiB(1))
    vol2_backend = RamVolume(S.from_MiB(1))
    vol2 = ErrorDevice(vol2_backend)

    cvol = CVolume(pyocf_ctx)
    cvol.add(vol1)
    cvol.add(vol2)
    cvol.destroy()


def test_add_max_subvolumes(pyocf_ctx):
    """
    title: Add maximum number of subvolumes.
    description: |
      Check that it is possible to add 16 subvolumes to composite volume.
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolumes are added without an error.
    steps:
      - Create composite volume
      - Add 16 RamVolume instances as subvolumes
      - Verify that no error occured
      - Destroy composite volume
    requirements:
      - composite_volume::max_composite_volumes
    """

    cvol = CVolume(pyocf_ctx)

    for i in range(16):
        vol = RamVolume(S.from_MiB(1))
        cvol.add(vol)

    vol = RamVolume(S.from_MiB(1))
    with pytest.raises(OcfError):
        cvol.add(vol)

    cvol.destroy()


def _cvol_io(cvol, addr, size, func, flags=0):
    io = cvol.new_io(
        queue=None, addr=addr, length=size, direction=IoDir.WRITE, io_class=0, flags=flags,
    )
    completion = OcfCompletion([("err", c_int)])
    io.callback = completion.callback
    data = Data(byte_count=size)
    io.set_data(data, 0)

    submit_fn = getattr(io, func)
    submit_fn()
    completion.wait()

    return int(completion.results["err"])


def test_basic_volume_operations(pyocf_ctx):
    """
    title: Perform basic volume operations.
    description: |
      Check that basic volume operations work on composite volume.
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolume is added without an error.
      - Submit io, submit flush and submit discard operations work properly.
    steps:
      - Create composite volume
      - Add mock volume as a subvolume
      - Submit io to composite volume and check if it was propagated
      - Submit flush to composite volume and check if it was propagated
      - Submit discard to composite volume and check if it was propagated
      - Destroy composite volume
    requirements:
      - composite_volume::volume_api
      - composite_volume::io_request_passing
    """
    count = {"flush": 0, "discard": 0, "io": 0}
    expected = {"flush": 0, "discard": 0, "io": 0}

    pyocf_ctx.register_volume_type(TraceDevice)

    addr = S.from_KiB(512).B
    size = S.from_KiB(4).B

    def trace(vol, io, io_type):
        if io_type == TraceDevice.IoType.Flush or int(io.contents._flags) & IoFlags.FLUSH:
            count["flush"] += 1
        elif io_type == TraceDevice.IoType.Discard:
            count["discard"] += 1
        else:
            assert io_type == TraceDevice.IoType.Data
            count["io"] += 1
        assert io.contents._dir == IoDir.WRITE
        assert io.contents._addr == addr
        assert io.contents._bytes == size

        return True

    backend = RamVolume(S.from_MiB(1))
    trace_dev = TraceDevice(backend, trace_fcn=trace)

    cvol = CVolume(pyocf_ctx)

    cvol.add(trace_dev)
    cvol.open()

    # verify data properly propagated
    ret = _cvol_io(cvol, addr, size, "submit")
    assert ret == 0
    expected["io"] += 1
    assert expected == count

    # verify flush properly propagated
    ret = _cvol_io(cvol, addr, size, "submit_flush", IoFlags.FLUSH)
    assert ret == 0
    expected["flush"] += 1
    assert expected == count

    # verify discard properly propagated
    ret = _cvol_io(cvol, addr, size, "submit_discard")
    assert ret == 0
    expected["discard"] += 1
    assert expected == count

    cvol.close()
    cvol.destroy()


@pytest.mark.skip(reason="not implemented")
def test_io_propagation_basic(pyocf_ctx):
    """
    title: Perform volume operations with multiple subvolumes.
    description: |
      Check that io operations are propagated properly to subvolumes.
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolumes are added without an error.
      - Operations are propagated properly.
    steps:
      - Create composite volume
      - Add 16 mock volumes as subvolumes
      - Submit io to each subvolume address range
      - Check if requests were propagated properly
      - Submit flush to each subvolume address range
      - Check if requests were propagated properly
      - Submit discard to each subvolume address range
      - Check if requests were propagated properly
      - Destroy composite volume
    requirements:
      - composite_volume::volume_api
      - composite_volume::io_request_passing
    """
    pass


@pytest.mark.skip(reason="not implemented")
def test_io_propagation_cross_boundary(pyocf_ctx):
    """
    title: Perform cross-subvolume operations.
    description: |
      Check that cross-subvolume operations are propagated properly.
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolumes are added without an error.
      - Operations are propagated properly.
    steps:
      - Create composite volume
      - Add 16 mock volumes as subvolumes
      - Submit io that cross address range boundary between each subvolume
      - Check if requests were propagated properly
      - Submit flush that cross address range boundary between each subvolume
      - Check if requests were propagated properly
      - Submit discard that cross address range boundary between each subvolume
      - Check if requests were propagated properly
      - Destroy composite volume
    requirements:
      - composite_volume::io_request_passing
    """
    pass


@pytest.mark.skip(reason="not implemented")
def test_io_propagation_multiple_subvolumes(pyocf_ctx):
    """
    title: Perform multi-subvolume operations.
    description: |
      Check that multi-subvolume operations are propagated properly.
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolumes are added without an error.
      - Operations are propagated properly.
    steps:
      - Create composite volume
      - Add 16 mock volumes as subvolumes
      - Submit series of ios that touch from 2 to 16 subvolumes
      - Check if requests were propated properly
      - Submit series of flushes that touch from 2 to 16 subvolumes
      - Check if requests were propagated properly
      - Submit series of discardss that touch from 2 to 16 subvolumes
      - Check if requests were propagated properly
      - Destroy composite volume
    requirements:
      - composite_volume::io_request_passing
    """
    pass


@pytest.mark.skip(reason="not implemented")
def test_io_completion(pyocf_ctx):
    """
    title: Composite volume completion order.
    description: |
      Check that composite volume waits for completions from all subvolumes.
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolumes are added without an error.
      - Operations are completed only after all subvolumes operations complete.
    steps:
      - Create composite volume
      - Add 16 mock volumes as subvolumes
      - Submit series of ios that touch from 2 to 16 subvolumes
      - Check if completions are called only after all subvolumes completed
      - Submit series of flushes that touch from 2 to 16 subvolumes
      - Check if completions are called only after all subvolumes completed
      - Submit series of discardss that touch from 2 to 16 subvolumes
      - Check if completions are called only after all subvolumes completed
      - Destroy composite volume
    requirements:
      - composite_volume::io_request_completion
    """
    pass


@pytest.mark.skip(reason="not implemented")
def test_io_completion(pyocf_ctx):
    """
    title: Composite volume error propagation.
    description: |
      Check that composite volume propagates errors from subvolumes.
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolumes are added without an error.
      - Errors from subvolumes are propagated to composite volume.
    steps:
      - Create composite volume
      - Add 16 ErrorDevice instances as subvolumes
      - Before each request arm one of ErrorDevices touched by this request
      - Submit series of ios that touch from 2 to 16 subvolumes
      - Check if errors were propagated properly
      - Submit series of flushes that touch from 2 to 16 subvolumes
      - Check if errors were propagated properly
      - Submit series of discardss that touch from 2 to 16 subvolumes
      - Check if errors were propagated properly
      - Destroy composite volume
    requirements:
      - composite_volume::io_error_handling
    """
    pass


@pytest.mark.skip(reason="not implemented")
def test_attach(pyocf_ctx):
    """
    title: Attach composite volume.
    description: |
      Check that it is possible to attach composite volume
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolumes are added without an error.
      - Cache attach succeeds.
    steps:
      - Create composite volume
      - Add 16 RamVolume instances as subvolumes.
      - Start cache and attach it using composite volume instance.
      - Verify that cache was attached properly.
      - Stop the cache.
      - Verify that cache was stopped.
    requirements:
      - composite_volume::cache_attach_load
    """
    pass


@pytest.mark.skip(reason="not implemented")
def test_load(pyocf_ctx):
    """
    title: Load composite volume.
    description: |
      Check that it is possible to attach composite volume
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolumes are added without an error.
      - Cache load succeeds.
    steps:
      - Create composite volume
      - Add 16 RamVolume instances as subvolumes.
      - Start cache and attach it using composite volume instance.
      - Stop the cache.
      - Start cache and load it using composite volume instance.
      - Verify that cache was loaded properly.
      - Stop the cache.
      - Verify that cache was stopped.
    requirements:
      - composite_volume::cache_attach_load
    """
    pass
