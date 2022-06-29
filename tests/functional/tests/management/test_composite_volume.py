#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
import random
from ctypes import POINTER, c_int, cast, c_void_p
from datetime import datetime
from threading import Event
from collections import namedtuple

from pyocf.ocf import OcfLib
from pyocf.types.volume import RamVolume, ErrorDevice, TraceDevice, IoFlags, VolumeIoPriv
from pyocf.types.cvolume import CVolume
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.cache import Cache
from pyocf.types.shared import OcfError, OcfErrorCode, OcfCompletion
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


def prepare_cvol_io(cvol, addr, size, func, flags=0):
    io = cvol.new_io(
        queue=None,
        addr=addr,
        length=size,
        direction=IoDir.WRITE,
        io_class=0,
        flags=flags,
    )
    completion = OcfCompletion([("err", c_int)])
    io.callback = completion.callback

    data = Data(size)
    io.set_data(data, 0)

    return io, completion


def cvol_submit_data_io(cvol, addr, size, flags=0):
    io, completion = prepare_cvol_io(cvol, addr, size, flags)

    io.submit()
    completion.wait()

    return int(completion.results["err"])


def cvol_submit_flush_io(cvol, addr, size, flags=0):
    io, completion = prepare_cvol_io(cvol, addr, size, flags)

    io.submit_flush()
    completion.wait()

    return int(completion.results["err"])


def cvol_submit_discard_io(cvol, addr, size, flags=0):
    io, completion = prepare_cvol_io(cvol, addr, size, flags)

    io.submit_discard()
    completion.wait()

    return int(completion.results["err"])


IoEvent = namedtuple("IoEvent", ["dir", "addr", "bytes"])


def setup_tracing(backends):
    io_trace = {}
    vols = []

    for vol in backends:
        trace_vol = TraceDevice(vol)
        vols.append(trace_vol)
        io_trace[trace_vol] = {
            TraceDevice.IoType.Flush: [],
            TraceDevice.IoType.Discard: [],
            TraceDevice.IoType.Data: [],
        }

    def trace(vol, io, io_type):
        if int(io.contents._flags) & IoFlags.FLUSH:
            io_type = TraceDevice.IoType.Flush

        io_trace[vol][io_type].append(
            IoEvent(io.contents._dir, io.contents._addr, io.contents._bytes)
        )

        return True

    for vol in vols:
        vol.trace_fcn = trace

    return vols, io_trace


def clear_tracing(io_trace):
    for io_types in io_trace.values():
        for ios in io_types.values():
            ios.clear()


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
    pyocf_ctx.register_volume_type(TraceDevice)

    addr = S.from_KiB(512).B
    size = S.from_KiB(4)

    backend = RamVolume(S.from_MiB(1))
    (vol,), io_trace = setup_tracing([backend])

    cvol = CVolume(pyocf_ctx)

    cvol.add(vol)
    cvol.open()

    # verify data properly propagated
    ret = cvol_submit_data_io(cvol, addr, size)
    assert ret == 0
    assert len(io_trace[vol][TraceDevice.IoType.Data]) == 1

    # verify flush properly propagated
    ret = cvol_submit_flush_io(cvol, addr, size, IoFlags.FLUSH)
    assert ret == 0
    assert len(io_trace[vol][TraceDevice.IoType.Flush]) == 1

    # verify discard properly propagated
    ret = cvol_submit_discard_io(cvol, addr, size)
    assert ret == 0
    assert len(io_trace[vol][TraceDevice.IoType.Discard]) == 1

    cvol.close()
    cvol.destroy()


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
    pyocf_ctx.register_volume_type(TraceDevice)

    vol_size = S.from_MiB(1)
    ram_vols = [RamVolume(vol_size * i) for i in range(1, 17)]

    vols, io_trace = setup_tracing(ram_vols)

    running_sum = S(0)
    vol_begin = []
    for v in ram_vols:
        vol_begin.append(S(running_sum))
        running_sum += S(v.size)

    cvol = CVolume(pyocf_ctx)
    for vol in vols:
        cvol.add(vol)

    cvol.open()

    # hit each subvolume at different offset (vol number * 1 KiB)
    io_addr = [i * S.from_KiB(1) + (vol_begin[i]) for i in range(len(vols))]
    io_size = S.from_KiB(12)

    for i, (vol, addr) in enumerate(zip(vols, io_addr)):
        ret = cvol_submit_data_io(cvol, addr, io_size)
        assert ret == 0

        ret = cvol_submit_flush_io(cvol, addr, io_size, IoFlags.FLUSH)
        assert ret == 0

        ret = cvol_submit_discard_io(cvol, addr, io_size)
        assert ret == 0

        for io_type in TraceDevice.IoType:
            ios = io_trace[vol][io_type]
            assert len(ios) == 1
            io = ios[0]
            assert io.dir == IoDir.WRITE
            assert io.addr == addr.B - int(vol_begin[i])
            assert io.bytes == io_size.B

    cvol.close()
    cvol.destroy()


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
    pyocf_ctx.register_volume_type(TraceDevice)

    vol_size = S.from_MiB(1)
    ram_vols = [RamVolume(vol_size * i) for i in range(16, 0, -1)]

    vols, io_trace = setup_tracing(ram_vols)

    running_sum = S(0)
    vol_begin = []
    for v in ram_vols:
        vol_begin.append(S(running_sum))
        running_sum += S(v.size)

    cvol = CVolume(pyocf_ctx)
    for vol in vols:
        cvol.add(vol)

    cvol.open()

    io_size = S.from_KiB(12)
    io_addr = [S(end) - (io_size / 2) for end in vol_begin[1:]]

    for i, addr in enumerate(io_addr):
        clear_tracing(io_trace)

        ret = cvol_submit_data_io(cvol, addr, io_size)
        assert ret == 0

        ret = cvol_submit_flush_io(cvol, addr, io_size, IoFlags.FLUSH)
        assert ret == 0

        ret = cvol_submit_discard_io(cvol, addr, io_size)
        assert ret == 0

        for io_type in TraceDevice.IoType:
            ios1 = io_trace[vols[i]][io_type]
            ios2 = io_trace[vols[i + 1]][io_type]

            assert len(ios1) == 1
            io = ios1[0]
            assert io.dir == IoDir.WRITE
            assert io.addr == int(vols[i].vol.size - (io_size / 2))
            assert io.bytes == io_size.B / 2

            assert len(ios2) == 1
            io = ios2[0]
            assert io.dir == IoDir.WRITE
            assert io.addr == 0
            assert io.bytes == io_size.B / 2

    cvol.close()
    cvol.destroy()


def test_io_propagation_entire_dev(pyocf_ctx):
    """
    title: Perform flush with 0 size
    description: |
      Check that flush operation with 0 size gets propagated to all
      subvolumes.
    pass_criteria:
      - Composite volume is created without an error.
      - Subvolumes are added without an error.
      - Flush is propagated to all subvolumes
    steps:
      - Create composite volume
      - Add 16 mock volumes as subvolumes
      - Submit flush with size == 0
      - Check if flush is sent to all subvolumes
      - Destroy composite volume
    requirements:
      - composite_volume::io_request_passing
    """
    pyocf_ctx.register_volume_type(TraceDevice)

    vol_size = S.from_MiB(1)
    ram_vols = [RamVolume(vol_size * (3 if i % 2 else 1)) for i in range(16)]

    vols, io_trace = setup_tracing(ram_vols)

    cvol = CVolume(pyocf_ctx)
    for vol in vols:
        cvol.add(vol)

    cvol.open()

    ret = cvol_submit_flush_io(cvol, 0, 0, IoFlags.FLUSH)
    assert ret == 0

    for vol, io_types in io_trace.items():
        assert len(io_types[TraceDevice.IoType.Flush]) == 1
        assert io_types[TraceDevice.IoType.Flush][0].addr == 0
        assert io_types[TraceDevice.IoType.Flush][0].bytes == 0

    cvol.close()
    cvol.destroy()


@pytest.mark.parametrize("rand_seed", [datetime.now().timestamp()])
def test_io_propagation_multiple_subvolumes(pyocf_ctx, rand_seed):
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
    random.seed(rand_seed)
    pyocf_ctx.register_volume_type(TraceDevice)

    vol_size = S.from_MiB(1)
    ram_vols = [RamVolume(vol_size) for _ in range(16)]

    vols, io_trace = setup_tracing(ram_vols)

    cvol = CVolume(pyocf_ctx)
    for vol in vols:
        cvol.add(vol)

    cvol.open()

    for subvol_count in range(2, len(vols) + 1):
        clear_tracing(io_trace)

        first_idx = random.randint(0, len(vols) - subvol_count)

        # I/O addres range start/end offsets within a subvolume
        start_offset = S.from_B(random.randint(0, vol_size.B // 512 - 1) * 512)
        end_offset = S.from_B(random.randint(0, vol_size.B // 512 - 1) * 512)

        size = (vol_size - start_offset) + (subvol_count - 2) * vol_size + end_offset
        addr = first_idx * vol_size + start_offset

        # aliases for subvolumes for easy referencing
        first = vols[first_idx]
        middle = vols[(first_idx + 1):(first_idx + subvol_count - 1)]
        last = vols[first_idx + subvol_count - 1]
        subvols = vols[(first_idx):(first_idx + subvol_count)]

        ret = cvol_submit_data_io(cvol, addr, size)
        assert ret == 0

        ret = cvol_submit_flush_io(cvol, addr, size, IoFlags.FLUSH)
        assert ret == 0

        ret = cvol_submit_discard_io(cvol, addr, size)
        assert ret == 0

        for vol in middle:
            for io in io_trace[vol].values():
                assert len(io) == 1
                assert io[0].addr == 0
                assert io[0].bytes == int(vol.vol.size)

        for io in io_trace[first].values():
            assert io[0].addr == int(start_offset)
            assert io[0].bytes == int(vol_size - start_offset)

        for io in io_trace[last].values():
            assert io[0].addr == 0
            assert io[0].bytes == int(end_offset)

    cvol.close()
    cvol.destroy()


@pytest.mark.parametrize("rand_seed", [datetime.now().timestamp()])
def test_io_completion(pyocf_ctx, rand_seed):
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
    random.seed(rand_seed)

    class PendingIoVolume(RamVolume):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pending_ios = []
            self.io_submitted = Event()

        def do_submit_io(self, io):
            self.pending_ios.append(("io", io))
            self.io_submitted.set()

        def do_submit_flush(self, flush):
            self.pending_ios.append(("flush", flush))
            self.io_submitted.set()

        def do_submit_discard(self, discard):
            self.pending_ios.append(("discard", discard))
            self.io_submitted.set()

        def wait_submitted(self):
            self.io_submitted.wait()
            self.io_submitted.clear()

        def resume_next(self):
            if not self.pending_ios:
                return False

            io_type, io = self.pending_ios.pop()
            if io_type == "io":
                super().do_submit_io(io)
            elif io_type == "flush":
                super().do_submit_flush(io)
            elif io_type == "discard":
                super().do_submit_discard(io)
            else:
                assert False

            return True

    pyocf_ctx.register_volume_type(PendingIoVolume)

    vol_size = S.from_MiB(1)
    vols = [PendingIoVolume(vol_size) for _ in range(16)]

    cvol = CVolume(pyocf_ctx)
    for vol in vols:
        cvol.add(vol)

    cvol.open()

    for subvol_count in range(2, len(vols)):
        # start I/O at an offset in the first volume
        addr = vol_size / 2
        size = (subvol_count - 1) * vol_size

        for op, flags in [("submit", 0), ("submit_flush", IoFlags.FLUSH), ("submit_discard", 0)]:
            io = cvol.new_io(
                queue=None,
                addr=addr,
                length=size,
                direction=IoDir.WRITE,
                io_class=0,
                flags=flags,
            )
            completion = OcfCompletion([("err", c_int)])
            io.callback = completion.callback

            data = Data(size)
            io.set_data(data, 0)

            submit_fn = getattr(io, op)
            submit_fn()

            pending_vols = vols[:subvol_count]
            for v in pending_vols:
                v.wait_submitted()

            assert not completion.completed()

            random.shuffle(pending_vols)

            for v in pending_vols:
                assert not completion.completed()
                assert v.resume_next()
                assert not v.resume_next()

            assert completion.wait(timeout=10)
            assert int(completion.results["err"]) == 0

    cvol.close()
    cvol.destroy()


@pytest.mark.parametrize("rand_seed", [datetime.now().timestamp()])
def test_io_error(pyocf_ctx, rand_seed):
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
    random.seed(rand_seed)
    pyocf_ctx.register_volume_type(TraceDevice)

    vol_size = S.from_MiB(1)
    ram_vols = [RamVolume(vol_size) for _ in range(16)]
    err_vols = [ErrorDevice(rv, armed=False, error_seq_no={IoDir.WRITE: 0}) for rv in ram_vols]

    cvol = CVolume(pyocf_ctx)
    for vol in err_vols:
        cvol.add(vol)

    cvol.open()

    for subvol_count in range(2, len(err_vols)):
        # start I/O at an offset in the first volume
        addr = vol_size / 2
        size = subvol_count * vol_size

        error_idx = random.randrange(0, subvol_count)
        err_vols[error_idx].arm()

        # verify data properly propagated
        ret = cvol_submit_data_io(cvol, addr, size)
        assert ret == -OcfErrorCode.OCF_ERR_IO

        # verify flush properly propagated
        ret = cvol_submit_flush_io(cvol, addr, size, IoFlags.FLUSH)
        assert ret == -OcfErrorCode.OCF_ERR_IO

        # verdiscard discard properly propagated
        ret = cvol_submit_discard_io(cvol, addr, size)
        assert ret == -OcfErrorCode.OCF_ERR_IO

        err_vols[error_idx].disarm()

    cvol.close()
    cvol.destroy()


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

    vols = [RamVolume(S.from_MiB(3)) for _ in range(16)]
    cvol = CVolume(pyocf_ctx)
    for vol in vols:
        cvol.add(vol)

    cache = Cache.start_on_device(cvol, name="cache1")

    stats = cache.get_stats()
    assert stats["conf"]["attached"] is True, "checking whether cache is attached properly"
    assert stats["conf"]["volume_type"] == CVolume

    cache.stop()
    assert Cache.get_by_name("cache1", pyocf_ctx) != 0, "Try getting cache after stopping it"


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
    vols = [RamVolume(S.from_MiB(3)) for _ in range(16)]

    cvol = CVolume(pyocf_ctx)
    for vol in vols:
        cvol.add(vol)

    cache = Cache.start_on_device(cvol, name="cache1")

    cache.stop()

    cvol = CVolume(pyocf_ctx)
    for v in vols:
        cvol.add(v)

    cache = Cache.load_from_device(cvol, name="cache1", open_cores=False)

    stats = cache.get_stats()
    assert stats["conf"]["attached"] is True, "checking whether cache is attached properly"
    assert stats["conf"]["volume_type"] == CVolume

    cache.stop()
    assert Cache.get_by_name("cache1", pyocf_ctx) != 0, "Try getting cache after stopping it"
