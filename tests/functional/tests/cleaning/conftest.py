#
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

import pytest
from ctypes import c_uint64
from threading import Event

from pyocf.types.cleaner import Cleaner
from pyocf.ocf import OcfLib
from pyocf.time import reset_time


class ManualCleaner:
    """Controls cleaner iterations one at a time from the test.

    Suppresses background cleaner kicks (e.g. those issued by ALRU/ACP
    when dirty data is created) so the cleaner only runs when run() is
    called.  Each run() executes a single ocf_cleaner_run iteration and
    waits for its completion callback.
    """

    def __init__(self):
        self._done = Event()
        self.last_interval = None

    def _end_handler(self, cleaner, interval):
        state = Cleaner._cleaners.get(cleaner)
        if state is not None:
            state.last_interval = interval
        self.last_interval = interval
        self._done.set()

    def run(self, cache):
        """Kick one cleaner iteration and wait for it to complete."""
        self._done.clear()
        self.last_interval = None
        lib = OcfLib.getInstance()
        cleaner_ptr = None
        for ptr in Cleaner._cleaners:
            if lib.ocf_cleaner_get_cache(ptr) == cache.cache_handle.value:
                cleaner_ptr = ptr
                break
        assert cleaner_ptr is not None, "No cleaner registered for cache"
        Cleaner._default_kick(cleaner_ptr)
        assert self._done.wait(timeout=5), "Cleaner iteration timed out"
        cache.settle()

    def run_until_idle(self, cache):
        """Run iterations until the cleaner reports it has nothing to do.

        The cleaner returns interval == 0 from its end callback while it
        still has work to do (asking to be kicked again immediately) and
        a non-zero interval (the configured wake_up_time, in ms) once it
        is finished.  This loop keeps kicking the cleaner until that
        non-zero interval is reported.
        """
        for _ in range(10000):
            self.run(cache)
            if self.last_interval > 0:
                return
        raise AssertionError("Cleaner did not become idle after 10000 iterations")

    def install(self):
        Cleaner.set_kick_handler(lambda cleaner: None)
        Cleaner.set_end_handler(self._end_handler)

    def uninstall(self):
        Cleaner.set_end_handler(None)
        Cleaner.set_kick_handler(None)


@pytest.fixture
def manual_cleaner():
    mc = ManualCleaner()
    mc.install()
    yield mc
    mc.uninstall()
