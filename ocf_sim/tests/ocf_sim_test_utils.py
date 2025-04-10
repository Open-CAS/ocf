#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import subprocess
import os
import shutil

def create_temp_dir():
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    if not os.path.isdir(dname+'/temp'):
        os.mkdir(dname+'/temp')
    os.chdir(dname+'/temp')


def delete_temp_dir():
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    if os.path.isdir(dname+'/temp'):
        shutil.rmtree(dname+'/temp')


class UciSimRunner:
    def __init__(self, syn_trace_filename, out_csv_filename, cache_size_in_GiB = None, format = 'csv', extra_flags = None) -> None:
        self.args = ("../../ocf_sim", "-t", syn_trace_filename, "-o", format, "-O", out_csv_filename)
        if cache_size_in_GiB != None:
            self.args = (*self.args, "-c", "{}".format(cache_size_in_GiB))

        if extra_flags != None:
            self.args = (*self.args, extra_flags)


    def run(self):
        buf = ''
        popen = subprocess.Popen(self.args, stdout=subprocess.PIPE)
        for line in popen.stdout:
            buf += str(line)
        popen.wait()
        # self.output = popen.stdout.read()
        self.output = buf


class BlkTraceSeqFileCreator:
    def __init__(self, start_address_in_GiB, size_in_GiB, blctrace_filename, isWrite) -> None:
        self.WRITE_SIZE_IN_SECTORS = 32768
        self.SECTOR_SIZE = 512
        self.isWrite = isWrite
        self.size_in_sectors = size_in_GiB * 1024 * 1024 * 1024 / self.SECTOR_SIZE
        self.start_address_in_sectors = start_address_in_GiB * 1024 * 1024 * 1024 / self.SECTOR_SIZE
        self.blctrace_file = open(blctrace_filename, "w")


    def create_blctrace_file(self):
        current_address = int(self.start_address_in_sectors)
        current_timestamp = float(0)
        mj = 253
        min = 0
        cpu = 0
        seq_num = 1
        pid = 600
        event = 'Q'
        if self.isWrite:
            action = 'W'
        else:
            action = 'R'

        while (current_address + self.WRITE_SIZE_IN_SECTORS) <= self.size_in_sectors:
            self.blctrace_file.write("{},{} {} {} {} {} {} {} {} + {}\n".format(mj, min, cpu, seq_num, current_timestamp, pid,
                                                                                event, action, current_address, self.WRITE_SIZE_IN_SECTORS))
            seq_num += 1
            current_address += self.WRITE_SIZE_IN_SECTORS
            current_timestamp += 1

        self.blctrace_file.flush()
        self.blctrace_file.close()

