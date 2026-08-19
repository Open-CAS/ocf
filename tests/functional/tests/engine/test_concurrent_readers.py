#
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

import time
from ctypes import c_int
from threading import Lock

from pyocf.types.cache import Cache, CacheMode
from pyocf.types.core import Core
from pyocf.types.data import Data
from pyocf.types.io import IoDir
from pyocf.types.shared import CacheLineSize, OcfCompletion, SeqCutOffPolicy
from pyocf.types.volume import RamVolume
from pyocf.types.volume_core import CoreVolume
from pyocf.utils import Size

# Highest reader count that still fits in the 8 bit access counter without
# colliding with the OCF_CACHE_LINE_ACCESS_WR (0xFF) sentinel
MAX_CONCURRENT_READERS = 254

PATTERN = b"\xa5"


class HoldDevice(RamVolume):
    """RamVolume which is able to suspend completion of forwarded reads"""

    def __init__(self, size, uuid=None):
        super().__init__(size, uuid)
        self._lock = Lock()
        self._armed = False
        self._held = []

    def arm(self):
        with self._lock:
            self._armed = True

    def disarm(self):
        with self._lock:
            self._armed = False

    def held_count(self):
        with self._lock:
            return len(self._held)

    def release(self, count=None):
        with self._lock:
            if count is None:
                count = len(self._held)
            released, self._held = self._held[:count], self._held[count:]

        for io in released:
            super().do_forward_io(*io)

        return len(released)

    def do_forward_io(self, token, rw, addr, nbytes, offset):
        with self._lock:
            if self._armed and rw == IoDir.READ:
                self._held.append((token, rw, addr, nbytes, offset))
                return

        super().do_forward_io(token, rw, addr, nbytes, offset)


def _submit_read(vol, queue, addr, size):
    data = Data(size)
    io = vol.new_io(queue, addr, size, IoDir.READ, 0, 0)
    io.set_data(data)
    cmpl = OcfCompletion([("err", c_int)])
    io.callback = cmpl.callback
    io.submit()

    return cmpl, data


def _wait_for(predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)

    return predicate()


def _wait_stable(value_fn, queue, quiet=0.2, timeout=30):
    """Wait until value_fn() stops changing and the queue goes idle"""
    deadline = time.monotonic() + timeout
    value = value_fn()
    changed = time.monotonic()

    while time.monotonic() < deadline:
        time.sleep(0.005)
        current = value_fn()
        if current != value:
            value, changed = current, time.monotonic()
            continue
        if time.monotonic() - changed < quiet:
            continue
        # I/O submission may still be in progress in the queue thread
        if queue.settle():
            continue
        return value

    return value_fn()


def test_max_concurrent_readers(pyocf_ctx):
    """
    Submit more read hits on a single cache line than the 8 bit alock access
    counter is able to track and verify that:
      * no more than 254 readers hold the cache line at the same time,
      * the excess readers are queued on the waiters list and are served once
        an active reader releases the line,
      * releasing the readers doesn't trip ENV_BUG_ON() in
        ocf_alock_unlock_one_rd().
    """
    readers = MAX_CONCURRENT_READERS + 1

    pyocf_ctx.register_volume_type(HoldDevice)

    cache_device = HoldDevice(Size.from_MiB(50))
    core_device = RamVolume(Size.from_MiB(50))

    cache = Cache.start_on_device(
        cache_device, cache_mode=CacheMode.WT, cache_line_size=CacheLineSize.LINE_4KiB
    )
    core = Core.using_device(core_device)
    cache.add_core(core)
    cache.set_seq_cut_off_policy(SeqCutOffPolicy.NEVER)

    vol = CoreVolume(core)
    vol.open()
    queue = cache.get_default_queue()

    cl = int(CacheLineSize.LINE_4KiB)

    # Map exactly one cache line, so that every subsequent read of the first
    # cache line worth of core data is a hit on that very same cache line
    vol.sync_io(queue, 0, Data.from_bytes(PATTERN * cl), IoDir.WRITE)
    queue.settle()

    # From now on reads issued to the cache device are parked, so every read
    # hit holds its cache line read lock until released
    cache_device.arm()

    try:
        ios = [_submit_read(vol, queue, 0, cl) for _ in range(readers)]

        held = _wait_stable(cache_device.held_count, queue)

        assert held <= MAX_CONCURRENT_READERS, (
            "{} readers hold a single cache line at the same time - the 8 bit alock "
            "access counter reached 0x{:02X} (OCF_CACHE_LINE_ACCESS_WR), making the "
            "cache line indistinguishable from write locked".format(held, held)
        )
        assert held == MAX_CONCURRENT_READERS, (
            "only {} readers acquired the cache line - the access counter is not "
            "saturated, so the test no longer exercises the bug".format(held)
        )

        assert not any(cmpl.completed() for cmpl, _ in ios), (
            "no read may complete while the cache device holds it"
        )

        # The reader which didn't get the lock is parked on the alock waiters
        # list. Releasing a single reader must hand the lock over to it, which
        # then issues its own read to the cache device.
        cache_device.release(1)

        handed_over = _wait_stable(cache_device.held_count, queue)
        assert handed_over == held, (
            "reader waiting for the cache line was not resumed after an active "
            "reader released it ({} readers in flight, expected {})".format(handed_over, held)
        )
    finally:
        # Reads must never be left parked on the cache device - cache.stop()
        # waits for I/O in flight, so a failed assertion would hang the fixture
        # teardown instead of reporting the failure
        cache_device.disarm()
        cache_device.release()

    assert _wait_for(lambda: all(cmpl.completed() for cmpl, _ in ios)), "I/O not completed"
    queue.settle()

    assert sorted({int(cmpl.results["err"]) for cmpl, _ in ios}) == [0]
    assert sorted({data.get_bytes() for _, data in ios}) == [PATTERN * cl]

    cache.stop()
