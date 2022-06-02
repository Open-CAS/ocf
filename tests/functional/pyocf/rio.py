#
# Copyright(c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

from ctypes import c_int, c_void_p, CFUNCTYPE
from enum import Enum, auto
from random import Random
from dataclasses import dataclass
from datetime import timedelta, datetime
from itertools import cycle
from threading import Thread, Condition, Event
from copy import deepcopy

from pyocf.utils import Size
from pyocf.types.volume import Volume
from pyocf.types.io import Io, IoDir
from pyocf.types.data import Data


class ReadWrite(Enum):
    READ = auto()
    WRITE = auto()
    RANDREAD = auto()
    RANDWRITE = auto()
    RANDRW = auto()

    def is_random(self):
        return self in [self.RANDREAD, self.RANDWRITE, self.RANDRW]


class IoGen:
    def __init__(self, extent, blocksize=512, seed=0, random=False, randommap=True):
        self.random_gen = Random(seed)
        self.random = random
        self.randommap = randommap

        gen = list(range(extent[0].B, extent[0].B + extent[1].B, blocksize.B))
        self.cycle_len = len(gen)

        if random:
            self.random_gen.shuffle(gen)

        if self.randommap:
            self.gen = cycle(gen)
            self.gen_fcn = lambda: next(self.gen)
        else:
            self.gen = gen
            self.gen_fcn = lambda: self.random_gen.choice(self.gen)

    def __iter__(self):
        return self

    def __next__(self):
        return self.gen_fcn()


@dataclass
class JobSpec:
    readwrite: ReadWrite = ReadWrite.READ
    randseed: int = 1
    rwmixwrite: int = 50
    randommap: bool = True
    bs: Size = Size.from_B(512)
    offset: Size = Size(0)
    njobs: int = 1
    qd: int = 1
    size: Size = Size(0)
    io_size: Size = Size(0)
    target: Volume = None
    time_based: bool = False
    time: timedelta = None
    continue_on_error: bool = False

    def merge(self, other):
        # TODO implement
        return other


class Rio:
    class RioThread(Thread):
        def __init__(self, jobspec: JobSpec, queue):
            super().__init__()
            self.jobspec = jobspec
            self.queue = queue
            self.ios = Size(0)
            self.io_target = 0
            self.finish_time = None

            self.qd_condition = Condition()
            self.qd = 0

            self.stop_event = Event()

            self.errors = []

        def should_finish(self):
            if self.stop_event.is_set():
                return True

            if self.jobspec.time_based:
                if datetime.now() >= self.finish_time:
                    return True
            elif self.ios >= self.io_target:
                return True

            return False

        def get_io_cb(self):
            def cb(error):
                if error != 0:
                    self.errors.append(error)
                    if not self.jobspec.continue_on_error:
                        print(f"Aborting on error {error}")
                        self.abort()
                with self.qd_condition as c:
                    self.qd -= 1
                    self.qd_condition.notify_all()

            return cb

        def abort(self):
            self.stop_event.set()

        def run(self):
            iogen = IoGen(
                (self.jobspec.offset, self.jobspec.size - self.jobspec.offset),
                self.jobspec.bs,
                self.jobspec.randseed + hash(self.name),
                self.jobspec.readwrite.is_random(),
                self.jobspec.randommap,
            )

            if self.jobspec.time_based:
                self.finish_time = datetime.now() + self.jobspec.time
            else:
                if int(self.jobspec.io_size) != 0:
                    self.io_target = min(
                        self.jobspec.io_size, self.jobspec.size - self.jobspec.offset
                    )
                else:
                    self.io_target = self.jobspec.size - self.jobspec.offset

            # TODO randrw
            iodir = (
                IoDir.WRITE
                if self.jobspec.readwrite in [ReadWrite.WRITE, ReadWrite.RANDWRITE]
                else IoDir.READ
            )

            while not self.should_finish():
                with self.qd_condition:
                    self.qd_condition.wait_for(lambda: self.qd < self.jobspec.qd)

                data = Data(self.jobspec.bs)  # TODO pattern and verify
                io = self.jobspec.target.new_io(
                    self.queue, next(iogen), self.jobspec.bs, iodir, 0, 0,
                )
                io.set_data(data)
                io.callback = self.get_io_cb()
                self.ios += self.jobspec.bs
                io.submit()
                with self.qd_condition:
                    self.qd += 1

            with self.qd_condition:
                self.qd_condition.wait_for(lambda: self.qd == 0)

    def __init__(self):
        self.global_jobspec = JobSpec()
        self.jobs = []

        self._threads = []
        self.errors = {}
        self.error_count = 0

    def readwrite(self, rw: ReadWrite):
        self.global_jobspec.readwrite = rw
        return self

    def rwmixwrite(self, mix: int):
        self.global_jobspec.rwmixwrite = mix
        return self

    def rwmixread(self, mix: int):
        self.global_jobspec.rwmixwrite = 100 - mix
        return self

    def norandommap(self):
        self.global_jobspec.randommap = False
        return self

    def randseed(self, seed):
        self.global_jobspec.randseed = seed
        return self

    def bs(self, bs: Size):
        self.global_jobspec.bs = bs
        return self

    def offset(self, offset: Size):
        self.global_jobspec.offset = offset
        return self

    def njobs(self, njobs: int):
        self.global_jobspec.njobs = njobs
        return self

    def qd(self, qd: int):
        self.global_jobspec.qd = qd
        return self

    def target(self, target: Volume):
        self.global_jobspec.target = target
        return self

    def add_job(self, job: JobSpec):
        self.jobs.append(job)
        return self

    def size(self, size: Size):
        self.global_jobspec.size = size
        return self

    def io_size(self, size: Size):
        self.global_jobspec.io_size = size
        return self

    def time_based(self):
        self.global_jobspec.time_based = True
        return self

    def time(self, time: timedelta):
        self.global_jobspec.time = time
        return self

    def continue_on_error(self):
        self.global_jobspec.continue_on_error = True
        return self

    def abort(self):
        for thread in self._threads:
            thread.abort()

        self.wait_for_completion()
        return self

    def wait_for_completion(self):
        for thread in self._threads:
            thread.join()
            self.errors.update({thread.name: thread.errors})
            self.error_count += len(thread.errors)

        return self

    def __del__(self):
        self.wait_for_completion()

    def clear(self):
        self._threads = []
        self.errors = {}

    def run(self, queues):
        self.run_async(queues)
        self.wait_for_completion()
        return self

    def run_async(self, queues):
        self.clear()

        jobs = deepcopy(self.jobs)

        if not jobs:
            jobs = [self.global_jobspec for _ in range(self.global_jobspec.njobs)]

        queues = cycle(queues)

        for job in jobs:
            spec = job.merge(self.global_jobspec)
            thread = Rio.RioThread(spec, next(queues))
            self._threads.append(thread)

        for thread in self._threads:
            thread.start()

        return self
