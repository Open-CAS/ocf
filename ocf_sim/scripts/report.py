#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#
import os
import pandas as pd
import re
from tabulate import tabulate
from collections import defaultdict
import argparse
import glob

ITER_STAT_START = "Usage statistics"
ITER_STAT_END = "OCF_RESET_COUNTERS"
CACHE_STAT = "printing stats for cache"
COMPLETION_TIME = "Total Completion Time:"
NUM_ITERATIONS = "num_traces = "

# The final and ONLY columns that will appear at the output report
# If you wish to add more columns to your report you need to add its name to the list
FINAL_COLUMNS_APPEARANCE = ["#", "log", "ver", "bench", "CSize", "CLevel", "Read hits(Requests)", "Read partial misses(Requests)",
                            "Read full misses(Requests)", "Read total(Requests)", "Write hits(Requests)",
                            "Write partial misses(Requests)", "Write full misses(Requests)", "Write total(Requests)",
                            "Reads from core(s)(4KiB Blocks)", "Writes to core(s)(4KiB Blocks)",
                            "Total to/from core(s)(4KiB Blocks)", "Reads from cache(4KiB Blocks)",
                            "Writes to cache(4KiB Blocks)",
                            "Total to/from cache(4KiB Blocks)", "tot_RD(4KiB Blocks)", "sav_WR(4KiB Blocks)",
                            "Prefetch from core(s): stream(4KiB Blocks)", "Prefetch to cache: stream(4KiB Blocks)",
                            "Prefetch: stream(Requests)", "Prefetch from core(s): locality(4KiB Blocks)",
                            "Prefetch to cache: locality(4KiB Blocks)", "Prefetch: locality(Requests)",
                            "Prefetch total(Requests)",
                            "Pass-Through reads(Requests)", "Pass-Through writes(Requests)",
                            "Pass-Through reads(4KiB Blocks)",
                            "Pass-Through writes(4KiB Blocks)", "Pass-Through total(4KiB Blocks)",
                            "Reads from exported object(s)(4KiB Blocks)", "Writes to exported object(s)(4KiB Blocks)",
                            "Total to/from exported object(s)(4KiB Blocks)", "Serviced requests(Requests)",
                            "Total requests(Requests)", "Occupancy(4KiB Blocks)", "Free(4KiB Blocks)",
                            "Clean(4KiB Blocks)",
                            "Dirty(4KiB Blocks)"]


def get_args():
    parser = argparse.ArgumentParser()

    # -vers VERSIONS -ts TIMESTAMP
    parser.add_argument("-vers", "--versions", nargs='+', type=str, dest="vers", default="",
                        help="List of running hypotheses")
    parser.add_argument("-ts", "--timestamp", dest="ts", default="", help="Runs timestamp")

    return parser.parse_args()


def get_interesting_files(args, logs_path):
    versions = args.vers
    ts = args.ts
    files = []
    for ver in versions:
        ver_files = glob.glob(fr"{logs_path}/log.*{ver}.*{ts}")
        if not ver_files:
            print(f"Can't find any log files with version name: '{ver}'")
        files.extend(ver_files)
    return files, ts


def parse_file(file_path, filename):
    missing_iterations = False
    with open(file_path, "r", encoding="utf8") as f:
        num_cache = 0
        iter = 0
        num_iter = 0
        list_of_iter_dicts = []
        iter_dict = {}
        list_per_iter = []
        filename_splited = filename.split(".")
        bench_csize = filename_splited[1].split("-")
        cache_size = bench_csize[-1]
        bench_name = "-".join(bench_csize[:-1])
        ver = filename_splited[2] if filename_splited[2] != "us" else ".".join(filename_splited[2:-2])
        for line in f:
            if 'ERROR' in line or 'missing' in line:
                return
            if NUM_ITERATIONS in line:
                num_iter = line.replace('\n', '').split(NUM_ITERATIONS)[-1]
                num_iter = int(num_iter) if num_iter else 1
            if CACHE_STAT in line:
                if iter_dict:
                    list_per_iter.append(iter_dict)
                    iter_dict = {}
                num_cache = int(line.replace('\n', '').split(CACHE_STAT)[-1])
            elif ITER_STAT_START in line:
                iter_dict = {
                    "#": iter + 1,
                    "log": filename,
                    "ver": ver,
                    "bench": bench_name,
                    "CSize": cache_size,
                    "CLevel": num_cache
                }
                split_char = line.split(ITER_STAT_START)[1].replace(' ', '')[0]
            elif COMPLETION_TIME in line:
                if iter_dict:
                    list_per_iter.append(iter_dict)
                    iter_dict = {}
                split_line = line.split(',')
                tot_dict = {}
                sec = 'sec'
                for tot, txt in dict(zip([f'tot_CT({sec})', f'tot_VTS({sec})', f'tot_CRT({sec})'], split_line)).items():
                    if sec in txt:
                        list_txt = txt.split()
                        tot_dict[tot] = int(list_txt[list_txt.index(sec)-1])
                for i, it_dict in enumerate(list_per_iter):
                    list_per_iter[i].update(tot_dict)
            elif ITER_STAT_END in line:
                if iter_dict:
                    list_per_iter.append(iter_dict)
                    iter_dict = {}
                iter += 1
                list_of_iter_dicts.extend(list_per_iter)
                list_per_iter = []
                num_cache = 0
            if iter_dict:
                if re.search(r'\d', line):
                    val = line[2:-3].split(split_char)
                    if len(val) == 4:
                        iter_dict[f"{val[0].rstrip(' ')}({val[-1].lstrip(' ')})"] = int(val[1])

        if num_iter+1 != iter:
            missing_iterations = True
        # add iterations info to a file dictionary
        combined_dict = defaultdict(list)
        for iter in list_of_iter_dicts:
            for key, val in iter.items():
                combined_dict[key].append(val)

        final_dict = dict(combined_dict)

    # Add values of total_RD and sav_WR
    sum_pf_f_core = [sum(final_dict[key][i] for key in final_dict if key.startswith("Prefetch from core(s):"))
                     for i in range(len(final_dict["#"]))]
    final_dict["tot_RD(4KiB Blocks)"] = [read_f_core_val + pf_val for read_f_core_val, pf_val in
                                         zip(sum_pf_f_core, final_dict['Reads from core(s)(4KiB Blocks)'])]

    final_dict["sav_WR(4KiB Blocks)"] = [final_dict["Reads from core(s)(4KiB Blocks)"][i] +
                                         final_dict["Writes to core(s)(4KiB Blocks)"][i] -
                                         final_dict["Writes to cache(4KiB Blocks)"][i]
                                         for i in range(len(final_dict["Reads from core(s)(4KiB Blocks)"]))]

    advanced_dict = final_dict.copy()
    advanced_columns_appearance = FINAL_COLUMNS_APPEARANCE.copy()
    # check if there is a new data in the log file that is not in the column_names list
    for col in final_dict.keys():
        if not col in FINAL_COLUMNS_APPEARANCE:
            advanced_columns_appearance.append(col)

    # check if there is data in column_names that is not appearing in this log file
    # (i.e. some prefetch algorithm is turned off in this run)
    for col in FINAL_COLUMNS_APPEARANCE:
        if not col in final_dict.keys():
            final_dict[col] = [0] * len(list(final_dict.values())[0])
            advanced_dict[col] = [0] * len(list(advanced_dict.values())[0])

    # rearranging the final dataframe of this log file so it will be as the arrangement in FINAL_COLUMNS_APPEARANCE
    final_df = pd.DataFrame.from_dict(final_dict)
    final_df = final_df[FINAL_COLUMNS_APPEARANCE]
    advanced_df = pd.DataFrame.from_dict(advanced_dict)
    advanced_df = advanced_df[advanced_columns_appearance]

    if len(advanced_columns_appearance) != len(FINAL_COLUMNS_APPEARANCE):
        return [final_df, advanced_df, missing_iterations]

    return [final_df, final_df, missing_iterations]


def extracting_data_from_files(logs_path, files, ts):
    final_df = pd.DataFrame()
    advanced_df = pd.DataFrame()
    error_files = []
    error_files_missing_iteration = []
    for file_full_path in files:
        file = os.path.basename(file_full_path)
        if os.path.exists(file_full_path and os.path.isfile(file_full_path)):
            dfs = parse_file(file_full_path, file)
            if dfs is None:
                error_files.append(file)
                continue
            if dfs[2]:
                error_files_missing_iteration.append(file)
            if len(dfs[0].columns) != len(dfs[1].columns):
                advanced_df = pd.concat([advanced_df, dfs[1]])
            final_df = pd.concat([final_df, dfs[0]])

    if not final_df.empty:
        if len(error_files_missing_iteration):
            print('Logs with missing iterations:', *error_files_missing_iteration, sep='\n\t')

        with pd.ExcelWriter(f"{logs_path}/us_report_{ts}.xlsx", engine='xlsxwriter') as writer:
            # Fill NaN values with zeros
            final_df = final_df.fillna(0)
            final_df = final_df.sort_values(['log', '#'])
            
            # save output to file in 'logs' repository
            final_df.to_excel(writer, sheet_name='Result', index=False)

            # If there were more columns of data in the log files, output another file with the new columns in it
            if not advanced_df.empty:
                advanced_df = advanced_df.fillna(0)
                advanced_df = advanced_df.sort_values(['log', '#'])
                advanced_df.to_excel(writer, sheet_name='Advanced', index=False)

            total_data = final_df.groupby('log').sum().drop(['#'], axis=1).reset_index()
            total_data.to_excel(writer, sheet_name='Total Data', index=False)

            stats = final_df.assign(log=final_df['log'].apply(lambda x: '.'.join(x.split('.')[:-2]+x.split('.')[-1:])))
            stats = stats.groupby(['#', 'log', 'ver', 'bench']).describe().stack(1).reset_index().rename(columns={'level_4': 'stat'}).sort_values(['log', '#'])
            stats.to_excel(writer, sheet_name='Stats', index=False)

    if len(error_files):
        print('Errors in logs:', *error_files, sep='\n\t')


def main():

    path = os.path.dirname(os.path.split(os.path.realpath(__file__))[0])
    logs_path = f"{path}/logs"
    if not os.path.exists(logs_path):
        print(f"Can't find 'logs' folder under {path}")
        return

    args = get_args()
    if len(args.vers) < 1:
        print("Please provide at least one version name")
        return

    files, ts = get_interesting_files(args, logs_path)
    if not files:
        print("Can't find any log files with supplied version names")
        return

    extracting_data_from_files(logs_path, files, ts)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('have a problem to create the Excel report')
        print(e)
