#!/bin/bash
#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

BENCH="wordcount|kmeans|terasort|tpcds|tpcc_percona|tpch|tpcc_100|tpcc_200"
USAGE="Usage: $(basename $0) [-v] [-n] [-e env] [-d div] [-p percent_cs] [-r num_runs] [-k num_traces] [-m \"more_params\"] [-c min,max,quota] [-b \"BENCH|...\"] ... EXEC [EXEC] [EXEC] ...\nBENCH = <\"$BENCH\">"


verbosity=0
dry=0
num_runs=3
percent_cs=50
benchs=$BENCH
set_cpu=(0 64 8)

# Versions below are an example.
# Create yours, build ocf_sim and rename it using ./rename.sh, and replace
# versions below with your executables.
vers=(
	#us.wac6-1-pm0M
	#us.wac6-1-pm1M
	#us.wac6-1-pm2M
)

while getopts 'e:d:p:r:b:k:m:c:vnh' opt; do
	case "$opt" in
		v) verbosity=1;;
		n) dry=1;;
		e) env="-e $OPTARG";	echo "env=$env";;
		d) div="-d $OPTARG";	echo "div=$div";;
		p) percent_cs="$OPTARG";;
		r) num_runs="$OPTARG";;
		b) benchs="$OPTARG";;
		k) num_traces="-k $OPTARG";;
		m) more_params="-m $(echo "${OPTARG}" | sed -e 's/ /|/g')";;
		c) IFS=',' read -r -a set_cpu <<< "$OPTARG";;
		?|h)
			echo -e  $USAGE
			exit 1
			;;
	esac
done
echo
shift "$(($OPTIND -1))"

IFS='|' read -r -a benchs <<< "$benchs"

if [ $# -ge 1 ]; then
	vers=($@)
fi

# filter duplicate entries
vers=($(echo "${vers[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
# remove duplicate entries and keep the original order
benchs=($(echo "${benchs[@]}" | tr ' ' '\n' | cat -n | sort -u -k 2 | sort -k 1 | awk '{print $2}' | tr '\n' ' '))

if [ -z "$vers" ]; then
	echo -e "no vers\n${USAGE}"
	exit
fi

# checking if runall.lock file is locked, if true busy wait until it's free
until [ $dry -eq 1 ]  || ./canrun.sh ; do
	sleep 60
done

(
	if [ $dry -eq 0 ]; then
		# file descriptor
		exec {fd}<> /tmp/runall.lock
		# lock runall.lock file
		flock $fd
	fi

	echo "checking ${vers[@]}"

	# Assign groups of CPUs according to minimum and maximum CPU usage
	declare -A cpu
	for ((i=${set_cpu[0]};i<${set_cpu[1]};i+=${set_cpu[2]})); do
		cpu[$i-$((i+${set_cpu[2]}-1))]=""
	done

	# get the released CPUs taskset
	function get_cpus(){
		while true; do
			for key in "${!cpu[@]}"; do
				val=${cpu[${key}]}
				if [[ $val == "" ]] || (( $(ps -ef | grep $val | wc -l) == 1 )); then
					c="${key}"
					return
				fi
			done
			sleep 5
		done
	}

	date_time=$(date +%y%m%d-%H%M%S)
	is_first_run_started=true

	for bench in ${benchs[@]}; do
		for r in $(seq 1 $num_runs); do
			for ver in ${vers[@]}; do
				get_cpus
				cmd="$more_params $num_traces -r $r -b $bench -c $c $env $div -u ${ver} -p $percent_cs -t $date_time"
				if [ $verbosity -eq 1 ]; then cmd="-v $cmd"; fi
				if [ $dry -eq 1 ]; then cmd="-n $cmd"; fi

				rst=$(./runme.sh $cmd)
				lines=(${rst//\n/ })
				last_line=${lines[-1]} # Get the last line of the array.

				if [[ "$last_line" == *"pid="* ]]; then
					if $is_first_run_started; then
						is_first_run_started=false
						echo -e "Starting runs\n"
					fi

					# Extract the PID from the end of the string supplied by runme.sh
					pid=$(echo "$last_line" | tr '=' '\n' | tail -n 1)
					if [ -n "$pid" ] && [ "$pid" -eq "$pid" ] 2>/dev/null; then
						cpu[${c}]="${pid}"
					fi
				fi
				echo "${rst}"
			done;
		done;
	done;

	function is_cpu_free() {
		local pids=""
		for v in "${cpu[@]}" ; do
			if [ "$v" != "0" ]; then
				pids+="$v "
			fi
		done

		if (kill -0 $pids  2>/dev/null) ; then
			return 0
		else
			return 1
		fi
	}

	if [ $dry -eq 0 ]; then

		while is_cpu_free ; do
			sleep 1
		done

		# Activate the venv
		source /raid/home/us_report_venv/bin/activate
		vers_string=$(printf " %s" "${vers[@]}")
		FILES="$(python report.py -vers $vers_string -ts $date_time)"
		files_string=$(printf "%s " "${FILES[@]}")
		deactivate

		cur_dir=${PWD%/*}
		us_report="$cur_dir"/logs/us_report_"$date_time".xlsx
		report_path="$USER"/us_report_"$date_time".xlsx

		email_string="Hello "$USER"! \n\nYour ocf_sim run from "$date_time" has ended for hypotheses: \n$vers_string.\n\n"
		web_dir="/BigDisk/ocffiles/web/reports"

		if [ -f $us_report ]; then
			# Copy the report file to common folder where user can download it from windows
			if [ ! -d "$web_dir"/"$USER" ] ; then
				mkdir "$web_dir"/"$USER"
			fi
			cp $us_report "$web_dir"/"$USER"/
			sudo chown -Rv www-data "$web_dir"/"$report_path"

			email_string+=$"The report file is ready in '$us_report'\n\nIn order to download the report on windows click here:\nhttp://gitlab.om.lan:8099/root/reports/"$report_path" \n\n"
		fi

		# Check if all logs finished successfully
		if [[ -z "${files_string// }" ]] ; then
			email_string+=$"All runs finished successfully"
		else
			email_string+=$"The runs failed because:\n\t"$files_string""
		fi

		# Send the email
		sendMailAdmin $(userinfo "$USER" email) "ocf_sim runall finished!" "$email_string"
	fi

	echo "Finished"
) &
