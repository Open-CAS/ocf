#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import os
import pandas as pd
from ocf_sim_test_utils import UciSimRunner
from ocf_sim_test_utils import BlkTraceSeqFileCreator
import ocf_sim_test_utils

def test_occupancy_recommendation_50():
    ocf_sim_test_utils.create_temp_dir()
    out_csv_file_name = 'occupancy_recommendation.csv'
    trace_filename = 'occupancy_50_percnt'
    creator = BlkTraceSeqFileCreator(start_address_in_GiB=0, size_in_GiB=1, blctrace_filename=trace_filename, isWrite=True)
    creator.create_blctrace_file()
    # run ocf_sim with cache size 2 GiB
    runner = UciSimRunner(trace_filename, out_csv_file_name, 2)
    runner.run()
    assert os.path.exists(out_csv_file_name)
    df = pd.read_csv(out_csv_file_name)
    last_row  = df.iloc[-1]
    print(runner.output)
    assert last_row['Occupancy [%]'] == 50
    assert 'Recommended cache size: 1 GiB' in str(runner.output)
    ocf_sim_test_utils.delete_temp_dir()

def test_occupancy_recommendation_75():
    ocf_sim_test_utils.create_temp_dir()
    out_csv_file_name = 'occupancy_recommendation_75.csv'
    trace_filename = 'occupancy_75_percnt'
    creator = BlkTraceSeqFileCreator(start_address_in_GiB=0, size_in_GiB=3, blctrace_filename=trace_filename, isWrite=True)
    creator.create_blctrace_file()
    # run ocf_sim with cache size 2 GiB
    runner = UciSimRunner(trace_filename, out_csv_file_name, 4)
    runner.run()
    assert os.path.exists(out_csv_file_name)
    df = pd.read_csv(out_csv_file_name)
    last_row  = df.iloc[-1]
    print(runner.output)
    assert last_row['Occupancy [%]'] == 75
    assert 'Recommended cache size: 3 GiB' in str(runner.output)
    ocf_sim_test_utils.delete_temp_dir()

def test_read_hit_recommendation_75():
    ocf_sim_test_utils.create_temp_dir()
    out_csv_file_name = 'read_hit_recommendation.csv'
    trace_filename_write = 'read_hit_100_percnt_write'
    trace_filename_read = 'read_hit_75_percnt_read'
    creator = BlkTraceSeqFileCreator(start_address_in_GiB=0, size_in_GiB=4, blctrace_filename=trace_filename_write, isWrite=True)
    creator.create_blctrace_file()
    creator = BlkTraceSeqFileCreator(start_address_in_GiB=1, size_in_GiB=3, blctrace_filename=trace_filename_read, isWrite=False)
    creator.create_blctrace_file()
    # run ocf_sim with cache size 2 GiB
    runner = UciSimRunner(trace_filename_write + ',' + trace_filename_read, out_csv_file_name, 4, 'csv', '-r')
    runner.run()
    assert os.path.exists(out_csv_file_name)
    df = pd.read_csv(out_csv_file_name)
    last_row  = df.iloc[-1]
    print(runner.output)
    assert last_row['Occupancy [%]'] == 100
    assert 'Recommended cache size: 3 GiB' in str(runner.output)
    ocf_sim_test_utils.delete_temp_dir()
