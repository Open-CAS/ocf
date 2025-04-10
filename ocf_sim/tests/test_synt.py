#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import os
import pandas as pd
from ocf_sim_test_utils import UciSimRunner
import ocf_sim_test_utils

def create_trace_file(filename, content):
    with open(filename, "w") as blctrace_file:
        blctrace_file.write(content)
        blctrace_file.close()


def create_syn_read_file(filename):
    demo_io = '  8,5    8 11155961  0.0 449527  Q   R 6923791968 + 32 [mysqld]\n'   \
    '  8,5    8 11155961  1.0 449527  Q   R 6923791968 + 32 [mysqld]\n'             \
    '  8,5    8 11155961  3.0 449527  Q   R 6923791968 + 32 [mysqld]\n'             \
    '  8,5    8 11155961  4.0 449527  Q   R 6923791968 + 32 [mysqld]\n'
    create_trace_file(filename, demo_io)

def create_syn_read_miss_file(filename):
    demo_io = '  8,5    8 11155961  0.0 449527  Q   R 6923791968 + 32 [mysqld]\n'   \
    '  8,5    8 11155961  1.0 449527  Q   R 6923790000 + 32 [mysqld]\n'             \
    '  8,5    8 11155961  0.0 449527  Q   R 0 + 32 [mysqld]\n'                      \
    '  8,5    8 11155961  1.0 449527  Q   R 4923790000 + 32 [mysqld]\n'
    create_trace_file(filename, demo_io)

def create_syn_write_file(filename):
    demo_io = '  8,5    8 11155961  0.0 449527  Q   W 6923791000 + 32 [mysqld]\n'   \
    '  8,5    8 11155961  1.0 449527  Q   W 6923791000 + 32 [mysqld]\n'             \
    '  8,5    8 11155961  3.0 449527  Q   W 6923791000 + 32 [mysqld]\n'             \
    '  8,5    8 11155961  4.0 449527  Q   W 6923791000 + 32 [mysqld]\n'
    create_trace_file(filename, demo_io)


def test_syn_read():
    ocf_sim_test_utils.create_temp_dir()
    out_csv_file_name = 'syn_read.csv'
    syn_trace_filename = 'syn_read'
    create_syn_read_file(syn_trace_filename)

    runner = UciSimRunner(syn_trace_filename, out_csv_file_name, 10)
    runner.run()
    assert os.path.exists(out_csv_file_name)
    df = pd.read_csv(out_csv_file_name)
    last_row  = df.iloc[-1]
    assert last_row['Read total [Requests]'] == 4
    assert last_row['Read full misses [Requests]'] == 1
    assert last_row['Read hits [Requests]'] == 3
    ocf_sim_test_utils.delete_temp_dir()


def test_syn_write():
    ocf_sim_test_utils.create_temp_dir()
    out_csv_file_name = 'syn_write.csv'
    syn_trace_filename = 'syn_write'
    create_syn_write_file(syn_trace_filename)
    runner = UciSimRunner(syn_trace_filename, out_csv_file_name, 10)
    runner.run()
    assert os.path.exists(out_csv_file_name)
    df = pd.read_csv(out_csv_file_name)
    last_row  = df.iloc[-1]
    assert last_row['Write total [Requests]'] == 4
    assert last_row['Write full misses [Requests]'] == 1
    assert last_row['Write hits [Requests]'] == 3
    ocf_sim_test_utils.delete_temp_dir()


def test_syn_read_and_write():
    ocf_sim_test_utils.create_temp_dir()
    out_csv_file_name = 'syn_read_write.csv'
    syn_trace_filename_write = 'syn_write'
    syn_trace_filename_read = 'syn_read'
    create_syn_read_file(syn_trace_filename_read)
    create_syn_write_file(syn_trace_filename_write)
    syn_trace_filename = syn_trace_filename_read + ',' + syn_trace_filename_write
    runner = UciSimRunner(syn_trace_filename, out_csv_file_name, 10)
    runner.run()
    assert os.path.exists(out_csv_file_name)
    df = pd.read_csv(out_csv_file_name)
    last_row  = df.iloc[-1]
    assert last_row['Write total [Requests]'] == 4
    assert last_row['Write full misses [Requests]'] == 1
    assert last_row['Write hits [Requests]'] == 3
    assert last_row['Read total [Requests]'] == 4
    assert last_row['Read full misses [Requests]'] == 1
    assert last_row['Read hits [Requests]'] == 3
    ocf_sim_test_utils.delete_temp_dir()


def test_syn_read_miss_only():
    ocf_sim_test_utils.create_temp_dir()
    out_csv_file_name = 'syn_read_miss.csv'
    syn_trace_filename_read = 'syn_read_miss'
    create_syn_read_miss_file(syn_trace_filename_read)
    runner = UciSimRunner(syn_trace_filename_read, out_csv_file_name, 10)
    runner.run()
    assert os.path.exists(out_csv_file_name)
    df = pd.read_csv(out_csv_file_name)
    last_row  = df.iloc[-1]
    assert last_row['Read total [Requests]'] == 4
    assert last_row['Read full misses [Requests]'] == 4
    assert last_row['Read hits [Requests]'] == 0
    ocf_sim_test_utils.delete_temp_dir()

def test_syn_read_after_write_hit():
    ocf_sim_test_utils.create_temp_dir()
    out_csv_file_name = 'syn_read_after_write_hit.csv'
    syn_trace_filename = 'syn_read_after_write_hit'
    demo_io_1 = '  8,5    8 11155961  0.0 449527  Q   W 6923791000 + 32 [mysqld]\n'
    demo_io_2 = '  8,5    8 11155961  1.0 449527  Q   R 6923791000 + 32 [mysqld]\n'
    demo_io_3 = '  8,5    8 11155961  3.0 449527  Q   W 6923791000 + 32 [mysqld]\n'
    demo_io_4 = '  8,5    8 11155961  4.0 449527  Q   R 6923791000 + 32 [mysqld]\n'
    create_trace_file(syn_trace_filename, demo_io_1+demo_io_2+demo_io_3+demo_io_4)
    runner = UciSimRunner(syn_trace_filename, out_csv_file_name, 10)
    runner.run()
    assert os.path.exists(out_csv_file_name)
    df = pd.read_csv(out_csv_file_name)
    last_row  = df.iloc[-1]
    assert last_row['Write total [Requests]'] == 2
    assert last_row['Read total [Requests]'] == 2
    assert last_row['Read full misses [Requests]'] == 0
    assert last_row['Read hits [Requests]'] == 2
    ocf_sim_test_utils.delete_temp_dir()

def test_syn_read_before_write_miss():
    ocf_sim_test_utils.create_temp_dir()
    out_csv_file_name = 'syn_read_before_write_miss.csv'
    syn_trace_filename = 'syn_read_before_write_miss'
    demo_io_1 = '  8,5    8 11155961  0.0 449527  Q   R 6923791000 + 32 [mysqld]\n'
    demo_io_2 = '  8,5    8 11155961  1.0 449527  Q   W 6923791000 + 32 [mysqld]\n'
    demo_io_3 = '  8,5    8 11155961  3.0 449527  Q   R 0 + 32 [mysqld]\n'
    demo_io_4 = '  8,5    8 11155961  4.0 449527  Q   W 0 + 32 [mysqld]\n'
    create_trace_file(syn_trace_filename, demo_io_1+demo_io_2+demo_io_3+demo_io_4)
    runner = UciSimRunner(syn_trace_filename, out_csv_file_name, 10)
    runner.run()
    assert os.path.exists(out_csv_file_name)
    df = pd.read_csv(out_csv_file_name)
    last_row  = df.iloc[-1]
    assert last_row['Write total [Requests]'] == 2
    assert last_row['Read total [Requests]'] == 2
    assert last_row['Read full misses [Requests]'] == 2
    assert last_row['Read hits [Requests]'] == 0
    ocf_sim_test_utils.delete_temp_dir()

def test_syn_read_table_output():
    ocf_sim_test_utils.create_temp_dir()
    out_table_file_name = 'syn_read.table'
    syn_trace_filename = 'syn_read'
    create_syn_read_file(syn_trace_filename)

    runner = UciSimRunner(syn_trace_filename, out_table_file_name, 10, 'table')
    runner.run()
    assert os.path.exists(out_table_file_name)
    out_csv_file = open(out_table_file_name, "r")
    index = 0
    for line in out_csv_file:
        index += 1
        if 'Read hits' in line:
            assert '3' in line
        if  'Read full misses' in line:
            assert '1' in line
        if  'Read total' in line:
            assert '4' in line
    ocf_sim_test_utils.delete_temp_dir()
