#!/bin/bash
#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

LOGS_DIR=../logs

div=1
BENCH="<wordcount|kmeans|terasort|tpcc_32|tpcds|tpcc_percona|tpch|tpcc_48|tpcc_64>"
# ocf_sim: any ocf_sim executable
USAGE="Usage: $(basename $0) -u ocf_sim -b $BENCH [-p percent_cs] [-c cpus] [-d div] [-e env] [-n] [-v] [-p trace_path] [-r num_run] [-t date_time] [-k num_traces] [-m \"more_params\"]"

dry=0
verbosity=0
num_run=1
cpus="0-1"
percent_cs=0.5
date=$(date +%y%m%d-%H%M%S)
declare -A cs_dict=( ["tpcc_percona"]=120 ["tpcc_100"]=108 ["tpcc_200"]=108 ["terasort"]=1135 ["wordcount"]=471 ["kmeans"]=481 ["tpcds"]=2000 ["tpch"]=87)
declare -A number_traces=( ["tpcc_percona"]=2 ["terasort"]=4 ["wordcount"]=4 ["kmeans"]=4 ["tpcds"]=99 ["tpch"]=44)

while getopts 'b:c:d:e:f:p:r:u:t:k:m:nvh' opt; do
	case "$opt" in
		u) ocf_sim="$OPTARG";;
		b) bench="$OPTARG";;
		p) percent_cs=$(awk "BEGIN {print ($OPTARG)/100}");;
		c) cpus="$OPTARG";;
		d) div="$OPTARG";;
		e) env="OCF_TS_FACTOR=$OPTARG";;
		f) trpath="$OPTARG";;
		r) num_run="$OPTARG";;
		t) date="$OPTARG";;
		n) dry=1;;
		v) verbosity=1;;
		k) num_traces="$OPTARG";;
		m) more_params=$(echo "${OPTARG}" | sed -e 's/|/ /g');;
		?|h)
			echo $USAGE
			exit 1
			;;
	esac
done

if [[ "$ocf_sim" != "ocf_sim"  && ! $ocf_sim =~ ^us. ]];then
	echo $ocf_sim : ocf_sim exec must be started \'us.\' or equal \'ocf_sim\'
	exit 1
fi

if [ -z "$bench" -o -z "$ocf_sim" ]; then
	echo $USAGE
	exit 1
fi

if [[ -z ${cs_dict[$bench]} ]]; then
	echo "You need to add $bench for cs_dict"
	exit 1
fi
# rounded cashe-size to the closest GB
power2() { echo "x=l($1)/l(2); scale=0; 2^((x+0.5)/1)" | bc -l; }
cs=$(power2 $(awk "BEGIN {print (${cs_dict[$bench]})*($percent_cs)}"))


if [[ -n ${number_traces[$bench]} ]]; then
	if [ -z "$num_traces" ]; then
		num_traces=${number_traces[$bench]}
	elif [ "$num_traces" -gt ${number_traces[$bench]} ]; then
		num_traces=${number_traces[$bench]}
		echo "the max number of traces for $bench is ${number_traces[$bench]}, your choice changed to the max for this bench"
	elif [ "$num_traces" -lt 1 ]; then
		num_traces=1
		echo "the min number of traces is 1, your choice changed to min"
	fi
	max_traces_idx=$(( num_traces-1 ))
else
	num_traces=1
fi

args="<<<<<\n
ARGS:\n
\tocf_sim     = $ocf_sim\n
\tbench       = $bench\n
\tpercent_cs  = $percent_cs\n
\tcpus        = $cpus\n
\tdiv         = $div\n
\tenv         = $env\n
\ttrpath      = $trpath\n
\tnum_run     = $num_run\n
\tdate        = $date\n
\tdry         = $dry\n
\tverbosity   = $verbosity\n
\tnum_traces  = $num_traces\n
\tmore_params = $more_params\n
>>>>>"

echo -e $args

if [ "$bench" == "tpcc_percona" ]; then
	if [ -z "$trpath" ]; then trpath=/raid/benchmark_traces/mysql/tpcc/2022-11-22-23-08-55; fi
	tracepref=$trpath/blktrace_out_2022-11-22-23-08-55_tpcc
	cmd="$(for i in ${tracepref}_prepare `eval echo $(echo ${tracepref}_exec_{0..$max_traces_idx})`; do echo "-t $i "; done)"
elif [ ${bench:0:4} == "tpcc" ]; then
	if [ -z "$trpath" ]; then
		if [ "$bench" == "tpcc_100" ]; then
			trpath=/bigger/home/algo_analysis/original_blktrace/tpcc_2024-01-02-11-26-24;
		elif [ "$bench" == "tpcc_200" ]; then
			trpath=/bigger/home/algo_analysis/original_blktrace/tpcc_2023-12-10-12-30-25;
		fi
	fi
	tracepref=$trpath/fci34-dn1
	cmd="-t ${tracepref}_prepare -t ${tracepref}_run_0_exec"
elif [ "$bench" == "tpcds" ]; then
	if [ -z "$trpath" ]; then trpath=/bigger/home/algo_analysis/original_blktrace/tpcds_2024-01-03-11-52-21; fi
	tracepref=$trpath/fci32
	cmd="$(for i in ${tracepref}_prepare `eval echo $(echo ${tracepref}_run_0-{1..$(($max_traces_idx+1))}_exec)`; do echo -n "-t $i "; done)"
elif [ "$bench" == "tpch" ]; then
	if [ -z "$trpath" ]; then trpath=/bigger/home/algo_analysis/original_blktrace/tpch_2024-01-01-19-35-45; fi
	tracepref=$trpath/fci40-dn1
	cmd="$(echo -n "-t ${tracepref}_prepare "; for ((i=0;i<=max_traces_idx;i++)); do echo -n "-t ${tracepref}_run_$((i/22))-$((i%22))_exec "; done)"
else
	if [ -z "$trpath" ]; then
		case "$bench" in
			terasort)	trpath=/bigger/home/algo_analysis/original_blktrace/terasort_2024-01-02-16-58-45;;
			wordcount)	trpath=/bigger/home/algo_analysis/original_blktrace/wordcount_2024-01-02-12-10-51;;
			kmeans)		trpath=/bigger/home/algo_analysis/original_blktrace/kmeans_2024-01-02-13-08-42;;
			*)
				echo $USAGE
				exit 1
				;;
		esac
	fi
	tracepref=$trpath/fci32
	cmd="$(for i in ${tracepref}_prepare `eval echo $(echo ${tracepref}_run_{0..$max_traces_idx}_exec)`; do echo -n "-t $i "; done)"
fi

if [ $verbosity -eq 1 ]; then cmd="-v $cmd"; fi

cs=$(printf %.1f $(echo $cs/$div | bc -l))
cmd="$more_params -c $cs $cmd"
cs=$(echo $cs | awk '{printf "%d", $NR}')

if [ ! -x ../$ocf_sim ]; then
	echo "skipping, The  ../$ocf_sim exec file does not exist"
	exit 1
fi

echo going to run: $env taskset -c $cpus ../$ocf_sim $cmd
if [ -n "$env" ]; then export $env; fi
if [ $dry -eq 0 ]; then
	log_file="${LOGS_DIR}/log.$bench-$cs.$ocf_sim.$num_run.$date"
	echo -e $args > $log_file
	taskset -c $cpus ../$ocf_sim $cmd >> $log_file &
	p_id=$!
	echo "pid=${p_id}"
fi
