#!/bin/bash
#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

# Checks if runall.lock file is free

# Catches if we run ocf_sim from the runall.sh script
# or if the file name exec ocf_sim is equal to 'ocf_sim' or starts with 'us.'
(
	# file descriptor
	exec {fd}<> /tmp/runall.lock
	export timeout_secs=1
	if ! flock -w $timeout_secs $fd || (( $(ps -ef | grep -E "(\.\./us\.|\.\./ocf_sim)" | wc -l) > 0)); then
		echo "Somebody else is currently running ocf_sim, so the script will enter to busy wait until the system is free"
		exit 1
	else
		echo "The system is free for your runs"
	fi
)
